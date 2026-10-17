# odoo-mcp-governed — hardened runtime image.
#
# * Application code is installed as root and owned by root: the process that
#   serves agents cannot modify the code it runs.
# * The server runs as an unprivileged user whose UID is configurable, so a
#   bind-mounted ./data directory owned by your host user stays writable.
# * Combine with the compose file's read_only rootfs, cap_drop and limits.
# * The Debian base carries CVEs that have no upstream fix yet. Rebuild
#   regularly so fixes arrive as soon as they exist:
#     docker compose build --pull && docker compose up -d
FROM python:3.12-slim

ARG APP_UID=1000
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DATA_DIR=/data \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8000

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
# Debian security fixes published since the base image was built are applied
# first. After installing: remove pip, setuptools and wheel (an installer has no
# business in a runtime image, and pip carried the image's only Python CVEs),
# and strip setuid/setgid bits so no binary can change identity even if
# no-new-privileges were ever dropped from the compose file.
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/* \
 && pip install ".[http]" \
 && rm -rf /app/src /root/.cache \
 && python -m pip uninstall -y pip setuptools wheel \
 && rm -f /usr/local/bin/pip* \
 && find / -xdev -type f -perm /6000 -exec chmod a-s {} + \
 && useradd --uid "${APP_UID}" --no-create-home --shell /usr/sbin/nologin app \
 && mkdir -p /data && chown app:app /data && chmod 700 /data

USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4)"

ENTRYPOINT ["odoo-mcp-governed"]
CMD ["http"]
