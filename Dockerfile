FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PYTHON_DOTENV_DISABLED=true \
    HOME=/var/lib/cybersentinel

WORKDIR /app

COPY requirements-runtime.txt /tmp/requirements-runtime.txt
RUN python -m pip install --no-cache-dir -r /tmp/requirements-runtime.txt \
    && python -m pip check \
    && groupadd --system --gid 10001 cybersentinel \
    && useradd --system --uid 10001 --gid 10001 --home-dir /var/lib/cybersentinel --no-create-home cybersentinel \
    && mkdir -p /var/lib/cybersentinel/workspace \
    && chown -R 10001:10001 /var/lib/cybersentinel

COPY . /app

USER 10001:10001
EXPOSE 8787

CMD ["python", "/app/bridge.py"]
