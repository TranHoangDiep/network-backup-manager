"""Fortinet FortiOS REST API backup driver (API token authentication).

Firmware compatibility (documented by Fortinet; verify against FNDN for your build):
* Endpoint: /api/v2/monitor/system/config/backup with scope=global, or
  scope=vdom&vdom=<name> for a single VDOM.
* FortiOS < 7.6.0 uses GET. From 7.6.0 the endpoint requires POST; GET returns
  HTTP 405 Method Not Allowed.
* FortiOS 7.4.5+ rejects API keys passed as the access_token URL parameter, so
  the token is always sent in the 'Authorization: Bearer' header.

Compatibility mechanism: the driver reads the firmware version from
/api/v2/monitor/system/status, tries the expected method first and falls back
to the other method only when the device answers 405. Nothing else is assumed.

Required on the FortiGate: a REST API admin whose trusthost includes this
server, with an access profile that can read the full configuration
(Fortinet documents super_admin for full backups; restricted profiles may
yield 403 or a partial backup).
"""
import logging
import re
import ssl

import httpx

from .base import (AuthenticationError, BaseDriver, ConfigResult, ConnectionFailedError,
                   ConnectionTimeoutError, DriverError, IncompleteConfigError, PermissionDeniedError,
                   TestResult, TLSVerificationError, UnsupportedError, non_empty_lines)

log = logging.getLogger(__name__)

STATUS_PATH = "/api/v2/monitor/system/status"
BACKUP_PATH = "/api/v2/monitor/system/config/backup"
POST_REQUIRED_FROM = (7, 6, 0)
VERSION_RE = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")


def parse_version(value):
    match = VERSION_RE.search(value or "")
    return tuple(int(x) for x in match.groups()) if match else None


class FortinetAPIDriver(BaseDriver):
    vendor = "fortinet"
    method = "api"
    platforms = ("fortinet",)
    config_types = ("running",)
    label = "Fortinet FortiOS (REST API)"

    def __init__(self, target, credential, options, transport: httpx.BaseTransport = None):
        super().__init__(target, credential, options)
        self.transport = transport  # injectable for tests

    # ------------------------------------------------------------ client ---
    def _verify(self):
        if not self.credential.verify_tls:
            log.warning("TLS certificate verification disabled by credential profile for %s", self.target.name)
            return False
        if self.credential.ca_cert_pem:
            try:
                return ssl.create_default_context(cadata=self.credential.ca_cert_pem)
            except ssl.SSLError as exc:
                raise TLSVerificationError(f"Invalid CA certificate in credential profile: {exc}") from None
        return True

    def _client(self) -> httpx.Client:
        if not self.credential.api_token:
            raise AuthenticationError("Credential profile has no API token")
        host = f"[{self.target.host}]" if ":" in self.target.host else self.target.host
        return httpx.Client(
            base_url=f"https://{host}:{self.target.port}",
            verify=self._verify(),
            timeout=httpx.Timeout(self.options.api_timeout, connect=self.options.conn_timeout),
            headers={"Authorization": f"Bearer {self.credential.api_token}",
                     "Accept": "application/json, text/plain, */*"},
            follow_redirects=False,
            trust_env=False,
            transport=self.transport,
        )

    def _request(self, client: httpx.Client, method: str, path: str, params: dict = None) -> httpx.Response:
        try:
            return client.request(method, path, params=params)
        except httpx.TimeoutException as exc:
            raise ConnectionTimeoutError(f"HTTPS request timed out ({type(exc).__name__})") from None
        except httpx.ConnectError as exc:
            message = str(exc)
            if "CERTIFICATE_VERIFY_FAILED" in message or "certificate verify failed" in message.lower():
                raise TLSVerificationError(
                    "TLS certificate verification failed. Install a trusted certificate on the FortiGate "
                    "or add its CA certificate to the credential profile.") from None
            raise ConnectionFailedError(f"HTTPS connection failed: {message[:200]}") from None
        except httpx.HTTPError as exc:
            raise ConnectionFailedError(f"HTTPS error: {type(exc).__name__}: {str(exc)[:200]}") from None

    @staticmethod
    def _raise_for_status(resp: httpx.Response) -> None:
        code = resp.status_code
        if code == 401:
            raise AuthenticationError("API token rejected (HTTP 401): token invalid/expired, or this server "
                                      "is not in the API user's trusthost list")
        if code == 403:
            raise PermissionDeniedError("HTTP 403: the API user lacks permission for this request "
                                        "(check access profile and VDOM assignment)")
        if 300 <= code < 400:
            raise AuthenticationError(f"Unexpected redirect (HTTP {code}); the API did not accept token authentication")
        if code == 404:
            raise UnsupportedError("HTTP 404: endpoint or VDOM not found on this FortiOS version")
        if code == 429:
            raise ConnectionFailedError("HTTP 429: FortiGate is rate limiting API requests")
        if code >= 500:
            raise ConnectionFailedError(f"FortiGate returned HTTP {code}")
        if code != 200:
            raise DriverError(f"Unexpected HTTP {code} from FortiGate")

    def _status(self, client: httpx.Client) -> dict:
        resp = self._request(client, "GET", STATUS_PATH)
        self._raise_for_status(resp)
        try:
            data = resp.json()
        except ValueError:
            raise DriverError("System status response is not valid JSON") from None
        results = data.get("results") or {}
        return {
            "version": data.get("version") or "",
            "build": data.get("build"),
            "serial": data.get("serial") or "",
            "hostname": results.get("hostname") or "",
            "model": results.get("model_name") or results.get("model") or "",
        }

    # -------------------------------------------------------- operations ---
    def test_connection(self) -> TestResult:
        with self._client() as client:
            info = self._status(client)
        return TestResult(True, f"API reachable: FortiOS {info['version'] or 'unknown'} "
                                f"{info['hostname']} serial {info['serial']}".strip(), info)

    @staticmethod
    def method_order(version) -> list:
        if version is not None and version >= POST_REQUIRED_FROM:
            return ["POST", "GET"]
        return ["GET", "POST"]

    def fetch_configs(self, config_types: list) -> list:
        params = {"scope": "vdom", "vdom": self.target.vdom} if self.target.vdom else {"scope": "global"}
        with self._client() as client:
            info = self._status(client)
            version = parse_version(info["version"])
            for method in self.method_order(version):
                resp = self._request(client, method, BACKUP_PATH, params=params)
                if resp.status_code == 405:
                    log.info("%s: backup endpoint rejected %s (405), trying alternative method",
                             self.target.name, method)
                    continue
                self._raise_for_status(resp)
                content = self._extract_config(resp)
                self.validate_config(content, scope=params["scope"])
                return [ConfigResult("running", content, "success",
                                     f"FortiOS {info['version'] or 'unknown'} via HTTP {method}",
                                     {"fortios_version": info["version"], "http_method": method,
                                      "scope": params["scope"]})]
        raise UnsupportedError("Backup endpoint rejected both GET and POST (HTTP 405)")

    @staticmethod
    def _extract_config(resp: httpx.Response) -> str:
        body = resp.content
        content_type = resp.headers.get("content-type", "").lower()
        head = body[:300].lstrip()
        if "json" in content_type or head.startswith(b"{"):
            try:
                data = resp.json()
            except ValueError:
                data = {}
            raise DriverError(
                "FortiGate returned a JSON response instead of a configuration file "
                f"(status={data.get('status')}, http_status={data.get('http_status')}, error={data.get('error')})")
        if head.lower().startswith((b"<!doctype", b"<html")) or b"<html" in head.lower():
            raise AuthenticationError("FortiGate returned an HTML page (login page?) instead of a configuration")
        # surrogateescape keeps any non-UTF-8 bytes intact for byte-exact storage
        return body.decode("utf-8", errors="surrogateescape")

    @staticmethod
    def validate_config(content: str, scope: str = "global") -> None:
        lines = non_empty_lines(content)
        if not lines:
            raise IncompleteConfigError("FortiGate returned an empty configuration")
        if not lines[0].startswith("#config-version="):
            raise IncompleteConfigError("Response does not start with the '#config-version=' header")
        if lines[-1].strip() != "end":
            raise IncompleteConfigError("FortiOS configuration does not end with 'end' (truncated?)")
        if scope == "global" and "config system global" not in content:
            raise IncompleteConfigError("Global backup has no 'config system global' section")
