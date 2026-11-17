FROM python:3.12-slim

ARG APP_UID=1000
ARG APP_GID=1000

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    FLASK_APP=run:app \
    NBM_DATA_DIR=/app/data \
    NBM_KEY_FILE=/app/keys/fernet.key

WORKDIR /app

RUN groupadd --gid ${APP_GID} app && \
    useradd --uid ${APP_UID} --gid ${APP_GID} --home-dir /app --no-create-home --shell /usr/sbin/nologin app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY --chown=app:app . .
RUN chmod 0755 docker/entrypoint.sh && \
    mkdir -p /app/data /app/keys && chown app:app /app/data /app/keys && chmod 0700 /app/keys

USER app
EXPOSE 8443
ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["web"]
