import httpx
import pytest

from app.drivers.base import (AuthenticationError, ConnectionTarget, ConnectionTimeoutError, DeviceCredential,
                              DriverError, DriverOptions, IncompleteConfigError, PermissionDeniedError,
                              UnsupportedError)
from app.drivers.fortinet_api import FortinetAPIDriver, parse_version

from .conftest import FORTI_CONFIG

TOKEN = "tok-ABCDEF123456"


def status_json(version):
    return {"http_method": "GET", "status": "success", "serial": "FG100FTK00000000", "version": version,
            "build": 3510, "results": {"hostname": "FG-HCM-01", "model_name": "FortiGate"}}


def make_driver(handler, vdom=""):
    target = ConnectionTarget(name="FG-HCM-01", host="10.10.10.1", port=443, platform="fortinet", vdom=vdom)
    cred = DeviceCredential(api_token=TOKEN, verify_tls=True)
    return FortinetAPIDriver(target, cred, DriverOptions(), transport=httpx.MockTransport(handler))


def router(version="v7.6.1", backup=None, calls=None):
    calls = calls if calls is not None else []

    def handler(request: httpx.Request):
        calls.append(request)
        assert request.headers["Authorization"] == f"Bearer {TOKEN}"
        assert TOKEN not in str(request.url)  # token never in URL
        if request.url.path == "/api/v2/monitor/system/status":
            return httpx.Response(200, json=status_json(version))
        if request.url.path == "/api/v2/monitor/system/config/backup":
            if backup:
                return backup(request)
            return httpx.Response(200, content=FORTI_CONFIG.encode(), headers={"content-type": "application/octet-stream"})
        return httpx.Response(404)
    return handler, calls


def test_parse_version():
    assert parse_version("v7.6.1") == (7, 6, 1)
    assert parse_version("garbage") is None


def test_post_used_on_76():
    handler, calls = router("v7.6.1")
    results = make_driver(handler).fetch_configs(["running"])
    assert results[0].content == FORTI_CONFIG
    assert results[0].meta["http_method"] == "POST"
    backup_call = [c for c in calls if c.url.path.endswith("/backup")][0]
    assert backup_call.method == "POST" and backup_call.url.params["scope"] == "global"


def test_get_used_on_72():
    handler, calls = router("v7.2.8")
    results = make_driver(handler).fetch_configs(["running"])
    assert results[0].meta["http_method"] == "GET"


def test_fallback_on_405():
    def backup(request):
        if request.method == "GET":
            return httpx.Response(405)
        return httpx.Response(200, content=FORTI_CONFIG.encode())
    handler, calls = router("v7.4.9", backup)
    results = make_driver(handler).fetch_configs(["running"])
    assert results[0].meta["http_method"] == "POST"
    assert [c.method for c in calls if c.url.path.endswith("/backup")] == ["GET", "POST"]


def test_both_methods_405():
    handler, _ = router("v7.4.9", lambda r: httpx.Response(405))
    with pytest.raises(UnsupportedError):
        make_driver(handler).fetch_configs(["running"])


def test_vdom_scope_params():
    vdom_config = FORTI_CONFIG.replace("config system global\n    set hostname \"FG-HCM-01\"\nend\n", "")
    handler, calls = router("v7.6.1", lambda r: httpx.Response(200, content=vdom_config.encode()))
    make_driver(handler, vdom="root").fetch_configs(["running"])
    params = [c for c in calls if c.url.path.endswith("/backup")][0].url.params
    assert params["scope"] == "vdom" and params["vdom"] == "root"


def test_invalid_token():
    def handler(request):
        return httpx.Response(401)
    with pytest.raises(AuthenticationError) as info:
        make_driver(handler).fetch_configs(["running"])
    assert not info.value.retryable


def test_insufficient_permission():
    handler, _ = router("v7.6.1", lambda r: httpx.Response(403))
    with pytest.raises(PermissionDeniedError):
        make_driver(handler).fetch_configs(["running"])


def test_json_error_body_not_saved():
    handler, _ = router("v7.6.1", lambda r: httpx.Response(200, json={"status": "error", "http_status": 500}))
    with pytest.raises(DriverError, match="JSON"):
        make_driver(handler).fetch_configs(["running"])


def test_html_login_page_rejected():
    handler, _ = router("v7.6.1", lambda r: httpx.Response(200, content=b"<html><body>login</body></html>",
                                                           headers={"content-type": "text/html"}))
    with pytest.raises(AuthenticationError):
        make_driver(handler).fetch_configs(["running"])


def test_incomplete_config():
    truncated = FORTI_CONFIG.rsplit("end", 1)[0]
    handler, _ = router("v7.6.1", lambda r: httpx.Response(200, content=truncated.encode()))
    with pytest.raises(IncompleteConfigError):
        make_driver(handler).fetch_configs(["running"])


def test_connection_timeout():
    def handler(request):
        raise httpx.ConnectTimeout("timed out", request=request)
    with pytest.raises(ConnectionTimeoutError) as info:
        make_driver(handler).fetch_configs(["running"])
    assert info.value.retryable


def test_test_connection_reports_version():
    handler, _ = router("v7.4.9")
    result = make_driver(handler).test_connection()
    assert result.ok and "7.4.9" in result.message and result.details["serial"] == "FG100FTK00000000"


def test_tls_verification_enabled_by_default():
    target = ConnectionTarget(name="x", host="10.10.10.1", port=443, platform="fortinet")
    driver = FortinetAPIDriver(target, DeviceCredential(api_token="t"), DriverOptions())
    assert driver._verify() is True


def test_non_utf8_bytes_preserved():
    raw = FORTI_CONFIG.encode().replace(b"FG-HCM-01\"", b"FG-\xff\xfe\"")
    handler, _ = router("v7.6.1", lambda r: httpx.Response(200, content=raw))
    content = make_driver(handler).fetch_configs(["running"])[0].content
    assert content.encode("utf-8", errors="surrogateescape") == raw
