# Security baseline

The author previously ran an internal Odoo MCP deployment and hardened it item
by item. That checklist is the minimum this project had to meet before
anything else was added. Each row says where the requirement lives here and
which test holds it in place. Rows marked **beyond** are additions that the
earlier deployment did not have.

## Authentication

| Requirement | Implementation | Test |
|---|---|---|
| JWT pinned to HS256; signature, `exp`, `iss` validated | `web/auth.py: verify_token` — also requires `iat` and `sub` | `test_http.py::TestMcpAuth` (`alg: none`, wrong key, expired, wrong issuer, no `exp`) |
| No secret → refuse to start; secret ≥ 32 chars | `config.py: Settings.require_http_secrets` | `TestFailClosed` |
| Malformed token → clean 401, not 500 | `verify_token` maps every PyJWT error to `AuthError` | `test_malformed_token_is_a_clean_401_not_a_500` |
| Revocation by rotating the secret | Tokens die with the secret; `TokenStore.current` shows a dead token as absent | — |
| **beyond:** token subject is the audited actor; one token per agent | `web/app.py: mcp_endpoint` | `test_token_subject_becomes_the_audited_actor` |
| **beyond:** failed authentications are audited | `mcp.auth` events with `auth_failed` | `test_failed_auth_is_audited` |

## Admin panel

| Requirement | Implementation | Test |
|---|---|---|
| Token page requires an admin session | `/token` redirects without one | `test_panel_requires_login` |
| Session cookie is 256 random bits, in memory, expiring (8 h) | `AdminSessions` (`secrets.token_urlsafe(32)`) | `test_session_cookie_is_random_and_hardened` |
| `ADMIN_PASSWORD` mandatory, ≥ 12 chars, no default | `require_http_secrets` | `TestFailClosed` |
| Login rate limit 5/min per IP | `RATE_LIMIT_LOGIN` | `test_login_is_rate_limited` |
| No XSS through profile data | All output escaped; **beyond:** zero JavaScript and a CSP without `script-src` | `test_injected_markup_in_audit_data_is_escaped`, `test_admin_pages_allow_no_script` |
| API keys never sent to the browser; empty key on edit keeps the old one | `Profile.public()` has no secret fields; `ProfileStore.save` | `test_api_keys_never_reach_the_browser`, `test_edit_with_empty_key_keeps_the_stored_key` |
| Logout | `POST /admin/logout` revokes the session | `test_logout_invalidates_the_session` |
| Profile names limited to `A-Z a-z 0-9 _ . -` | `PROFILE_NAME` | `test_profile_name_charset_is_enforced` |
| **beyond:** CSRF token on every admin form, `SameSite=Strict` | `csrf_matches` | `test_posts_without_csrf_are_refused` (mutation-checked) |
| **beyond:** admin actions in the tamper-evident chain | `Runtime.admin_action`, `record_login` | `test_hot_swap_changes_the_next_call`, `test_policy_change_applies_live_and_persists` |

## Model and method restrictions

| Requirement | Implementation | Test |
|---|---|---|
| Denylist of models that run Python, hold secrets or disable ACLs, enforced in every tool | `DEFAULT_DENIED_MODELS`, checked before any allowlist | `TestDenylistAndWildcard` |
| Denylist configurable (`NOT_ALLOWED_MODELS` still accepted) | `DENIED_MODELS` alias | `test_denylist_is_configurable` |
| `execute_method` blocks `sudo`, `with_user`, `with_env`, `_private` | `BLOCKED_METHODS` + `_` prefix rule | `test_environment_switching_is_always_blocked`, `test_private_methods_are_refused` |
| A block returns a readable error, not a 500 | MCP `isError` result with the reason | `test_policy_denial_is_a_tool_error_with_a_reason` |
| **beyond:** allowlists per operation (read / write / delete), default deny, `*` wildcard | `PolicyConfig` | `test_policy.py` |
| **beyond:** `unlink`/`write`/`create` cannot be laundered through `execute_method` | `BLOCKED_METHODS` | `test_cannot_launder_a_delete_through_unlink` |
| **beyond:** credential fields refused everywhere, including inside search domains | `SENSITIVE_FIELDS`, `domain_fields` | `test_password_oracle_through_a_domain` (mutation-checked) |

## Server protection

| Requirement | Implementation | Test |
|---|---|---|
| Body limit 25 MB, chunked included → 413 | `BodySizeLimit` counts bytes | `test_chunked_oversized_body_is_413` (mutation-checked) |
| `/docs`, `/redoc`, `/openapi.json` off | `FastAPI(docs_url=None, …)` | `test_api_docs_are_not_published` |
| `/health` does not leak connection errors | Returns only `reachable`/`unreachable` | `test_health_hides_connection_errors` |
| 500s carry no internal detail | Global exception handler | — |
| CSP, `X-Frame-Options`, `nosniff`, `no-store`, HSTS in HTTPS mode | `security_headers` middleware | `test_security_headers`, `test_hsts_only_in_https_mode` |
| `Mcp-Session-Id` validated, not reflected | `SESSION_ID` pattern | `test_malformed_session_id_is_rejected_not_reflected` |
| MCP rate limit with the real IP behind a proxy | `RateLimiter` + uvicorn `forwarded_allow_ips` | `test_mcp_rate_limit` |
| `ODOO_TIMEOUT` actually enforced | `OdooClient` passes a timeout to every request | verified live against a socket that never answers |

## Logs

| Requirement | Implementation | Test |
|---|---|---|
| Only tool, model, method and field names — never values | `AuditEvent` has no value fields; arguments are digested | `test_argument_values_are_never_stored` |
| **beyond:** hash-chained, optionally HMAC-sealed, verifiable from the CLI | `governance/audit.py` | `test_audit_chain.py` |
| Docker log rotation 3 × 10 MB | `docker-compose.yml` | — |

## Files with credentials

| Requirement | Implementation | Test |
|---|---|---|
| Written `0600`, atomically | `storage.write_private_json` | `test_secret_files_are_0600` |
| Profiles alone suffice, without `ODOO_*` | `ProfileStore` is the source of truth; env only bootstraps | — |
| **beyond:** audit database and its WAL files `0600`, data dir `0700` | `AuditStore` pre-creates the file | `test_audit_database_and_its_wal_files_are_private` |

## TLS

| Requirement | Implementation | Test |
|---|---|---|
| Certificate verification on by default, opt-out per profile | `ssl_verify` on `Profile`/`OdooClient` | — |

## Container

| Requirement | Implementation |
|---|---|
| Configurable UID so `./data` stays writable | `APP_UID` build arg |
| Code owned by root, read-only root filesystem | `Dockerfile`, `read_only: true` |
| `cap_drop: ALL`, `no-new-privileges` | `docker-compose.yml` |
| 512 MB, 1 CPU, 200 PIDs | `docker-compose.yml` |
| Own network | `mcp_net` |
| Secrets in `.env`, outside git and the image | `.gitignore`, `.dockerignore` |
| **beyond:** published on `127.0.0.1` only by default | `docker-compose.yml` |

## Network

| Requirement | Implementation |
|---|---|
| Docker bypasses UFW; restrict via `DOCKER-USER` | `deploy/firewall-docker.sh`, matching on the original published port so other containers listening on the same internal port are unaffected |
| **beyond:** egress limited to Odoo — no internet, no LAN, no other host services | `deploy/egress-docker.sh` (`DOCKER-USER` for forwarded traffic, `INPUT` for the Docker host itself; `--dry-run` prints the rules) |
| **beyond:** `/mcp` rejects foreign `Origin` headers (DNS rebinding) | `MCP_ALLOWED_ORIGINS`; localhost and `MCP_PUBLIC_URL` are accepted, clients without `Origin` are unaffected |
| **beyond:** rate limit per actor, batches capped and counted per message | `RATE_LIMIT_MCP`, `RATE_LIMIT_MCP_IP`, `RATE_LIMIT_AUTH_FAIL`, `MCP_MAX_BATCH` |

## Admin-managed policy

| Requirement | Implementation | Test |
|---|---|---|
| Enable/disable each of the 18 tools; disabled ones vanish from `tools/list` and are refused | `disabled_tools` | `test_disabled_tool_disappears_and_is_refused` |
| Edit blocked models and forbidden methods live, no restart | `PolicyStore` + engine swap | `test_policy_change_applies_live_and_persists` |
| Stored in `policy.json` (0600); `.env` is only the initial value | `PolicyStore` | same |
| Log viewer with filters and shortcuts; blocks in red | `/admin/logs` | `test_audit_page_renders_and_filters` |

## Known gap carried over, now fixed

The earlier deployment's `get_report` called a private ORM method that Odoo
refuses over RPC, so it never worked. Here it renders through Odoo's own
`/report/pdf/…` route with a web session, and is governed on the model the
report renders. It needs the profile password: Odoo does not accept API keys
for web sessions.
