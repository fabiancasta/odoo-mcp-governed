#!/usr/bin/env bash
# Build the disposable world a red-team job attacks, on a CI runner:
# PostgreSQL + a fresh Odoo 19 database, canary secrets, and governed built
# from the checked-out commit with the widest policy. Exports
# REDTEAM_ADMIN_PASSWORD, REDTEAM_TOKEN and REDTEAM_AGENT_TOKEN to $GITHUB_ENV.
#
# Images are pinned by digest for reproducible runs; Dependabot proposes bumps.
set -euo pipefail

ODOO_IMAGE="${ODOO_IMAGE:-odoo:19.0@sha256:076562619a5de059388d9f9d90545cb575799c04869610a5b20839893819b41b}"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-postgres:15@sha256:c961aa287d8698297cb26cdfadfbe9fd2cbaf77e53cfffe9636e8d8a1e4d842c}"

docker network create rt >/dev/null
docker run -d --name db --network rt -e POSTGRES_USER=odoo -e POSTGRES_PASSWORD=odoo \
  -e POSTGRES_DB=postgres "$POSTGRES_IMAGE" >/dev/null
until docker exec db pg_isready -U odoo >/dev/null 2>&1; do sleep 2; done
docker run --rm --network rt -e HOST=db -e USER=odoo -e PASSWORD=odoo \
  "$ODOO_IMAGE" odoo -d govtest -i base,contacts --stop-after-init
docker run -d --name web --network rt -p 127.0.0.1:8069:8069 \
  -e HOST=db -e USER=odoo -e PASSWORD=odoo "$ODOO_IMAGE" odoo --db-filter='^govtest$' >/dev/null
for _ in $(seq 1 60); do
  code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8069/web/login || true)
  [ "$code" = 200 ] && break; sleep 3
done
echo "odoo answered ${code}"

python3 redteam/canaries.py --url http://127.0.0.1:8069 --db govtest --out canaries.json

docker build -q -t governed:rt . >/dev/null
python3 - <<'PY'
import os, secrets
values = {
    "JWT_SECRET": secrets.token_urlsafe(48),
    "ADMIN_PASSWORD": secrets.token_urlsafe(24),
    "AUDIT_HMAC_KEY": secrets.token_urlsafe(32),
    "ODOO_URL": "http://web:8069", "ODOO_DB": "govtest",
    "ODOO_USERNAME": "admin", "ODOO_PASSWORD": "admin",
    "ODOO_ENVIRONMENT": "development",
    # Widest policy on purpose: the floor must hold on its own.
    "ALLOWED_MODELS": "*", "WRITABLE_MODELS": "*", "DELETABLE_MODELS": "*",
    "ALLOW_EXECUTE_METHOD": "true", "EXECUTE_METHOD_ALLOWLIST": "",
    "BUSINESS_HOURS": "00:00-23:59", "BUSINESS_DAYS": "mon,tue,wed,thu,fri,sat,sun",
    "BUSINESS_TIMEZONE": "UTC", "RISK_THROTTLE_SECONDS": "0",
    "DATA_DIR": "/data", "MCP_HOST": "0.0.0.0", "MCP_PORT": "8000",
}
with open("rt.env", "w") as f:
    f.writelines(f"{k}={v}\n" for k, v in values.items())
print(f"::add-mask::{values['ADMIN_PASSWORD']}")
with open(os.environ["GITHUB_ENV"], "a") as f:
    f.write(f"REDTEAM_ADMIN_PASSWORD={values['ADMIN_PASSWORD']}\n")
PY
mkdir -m 777 rtdata
docker run -d --name governed --network rt -p 127.0.0.1:8032:8000 \
  --env-file rt.env -v "$PWD/rtdata:/data" --read-only \
  --tmpfs /tmp:size=16m,mode=1777 --cap-drop ALL \
  --security-opt no-new-privileges:true governed:rt >/dev/null
for _ in $(seq 1 40); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' governed)" = healthy ] && break; sleep 2
done

token() {
  docker exec governed odoo-mcp-governed token --actor "$1" --hours 2 \
    | grep -o 'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
}
seed=$(token rt-seed)
llm=$(token rt-llm-attacker)
echo "::add-mask::${seed}"
echo "::add-mask::${llm}"
echo "REDTEAM_TOKEN=${seed}" >> "$GITHUB_ENV"
echo "REDTEAM_AGENT_TOKEN=${llm}" >> "$GITHUB_ENV"
echo "world ready: odoo govtest, governed on 127.0.0.1:8032"
