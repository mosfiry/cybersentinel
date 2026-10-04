FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="CyberSentinel" \
      org.opencontainers.image.description="Self-hosted single-host runtime"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PYTHON_DOTENV_DISABLED=true \
    HOME=/var/lib/cybersentinel

WORKDIR /app

COPY requirements-runtime.txt /tmp/requirements-runtime.txt
RUN python -m pip install --no-cache-dir --disable-pip-version-check -r /tmp/requirements-runtime.txt \
    && python -m pip check \
    && groupadd --system --gid 10001 cybersentinel \
    && useradd --system --uid 10001 --gid 10001 --home-dir /var/lib/cybersentinel --no-create-home cybersentinel \
    && mkdir -p /var/lib/cybersentinel/workspace \
    && chown -R 10001:10001 /var/lib/cybersentinel

COPY --chown=0:0 . /app

USER 10001:10001
STOPSIGNAL SIGTERM
RUN python -c "from workspace import Workspace"
EXPOSE 8787

CMD ["python", "/app/bridge.py"]
