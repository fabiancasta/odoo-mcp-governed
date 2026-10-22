# odoo-mcp-governed

An MCP server for Odoo where every tool call is policy-checked, risk-scored,
and written to a tamper-evident audit log before it is allowed to touch the
ERP.

Giving an AI agent write access to the system that holds your invoices,
customers and stock is a straightforward thing to build and a hard thing to
justify. The usual MCP server hands the model a set of tools and hopes. This
one assumes the agent will eventually do something wrong — because its
instructions changed, because it was prompt-injected, because its token
leaked — and is built so that when that happens the damage is bounded and the
evidence survives.

> **Status:** v0.3 — all 19 tools, stdio and HTTP transports, admin panel and
> Docker deployment work end to end against Odoo 19. 537 tests, 15 of them clicking through the panel in a real browser.

## What the operator gets

| | |
|---|---|
| **Panic switch** | One click refuses every agent call on the next request. The panel and the audit log keep running, and it survives restarts until you resume. |
| **Block one agent** | Refuse every call from one token; the other agents keep working. |
| **Undo with one click** | Every create, write and delete is journalled with its old and new values. Undo writes the old values back, deletes what was created, or recreates what was deleted. |
| **Human approval** | Deletes, bulk changes or `execute_method` can wait for a person. The agent gets a request number; you approve in the panel (and get a webhook or Telegram message); the agent repeats the exact call once. |
| **Live dashboard** | Calls per hour, blocked attempts by kind, most used models, agent risk meters — refreshed every ten seconds. |
| **Threshold console** | Faders for throttle and block scores, delete bursts, call rate and risk memory, applied live and audited. |
| **Permissions by app** | Odoo's own models grouped by app with read/write/delete ticks. Models installed later show as "new — not reviewed" and stay blocked until you tick them. |
| **Sandbox profiles** | For test databases: model lists off and risk only observed, while the denylist, credential fields and audit stay on. Never on production. |
| **Activity report** | A printable "what your AI did" page per client and period — counts, refusals, changes — with no record values, ready to send as a PDF. |
| **Several clients** | Pin each agent's token to its client's Odoo profile; switching the active profile can never send it to another client's database. |
| **Two layers, in plain words** | The Permissions page first shows what Odoo itself lets the profile's user do — asked of Odoo, per app — then three brakes on every agent: may change, may delete, a person approves deletes and bulk changes. Passwords, keys, certificates, modules, code, users and settings stay out whatever the switches say. Per-app and per-model lists are under Advanced. |
| **Permissions per profile** | One server, several Odoo (Spain, Colombia…): each profile can have its own lists, or follow the default ones. Each app gets one level in one click — none, read, change, delete — with a selector per model to fine-tune, a search box, and Odoo's system models kept apart. |
| **Archive or delete agents** | Revokes every token, blocks the agent and hides it; restore any time. The audit log keeps its history. |
| **Clickable dashboard** | Tabs (summary, Odoo profiles, policy). Every number, bar, refusal kind and model opens the audit log filtered to exactly those events. |
| **Agent tree** | Each agent — with a rule or only seen in the audit log — opens as a tree: profiles → what it can really read, change and delete there, model and tool limits, record scope, tokens, activity; with + to add. |
| **Agent registry** | Every token is listed and can be revoked on its own, or all of one agent's at once — no `JWT_SECRET` rotation. A rule per agent narrows the policy: fewer models or tools, read-only, a daily call quota, one pinned profile. |
| **Record scope** | A domain per model, e.g. a WhatsApp bot sees only `res.partner` `id = {partner}` and that customer's `sale.order`. `{partner}` comes from the token's signed variables, so one rule serves one token per customer. Searches are ANDed with the scope, ids outside it are refused, new records get the scope's values. |
| **Injection warning** | Record content is data. Text in it that addresses an AI ("ignore previous instructions…") still comes back, plus a separate warning to the agent and an audit entry. |
| **Less approval fatigue** | Approve all similar pending requests at once, or a kind of call (agent + tool + model) for 30 min, 2 h or 8 h, up to 50 uses — never for modules or code. A burst of similar requests notifies once. |
| **Two-factor panel** | `ADMIN_TOTP_SECRET` adds an authenticator-app code to the panel login; a code works once. |

## How a call is handled

Tools cannot reach Odoo except through the governance engine. Every call
passes three stages, in this order:

```
ToolCall
   │
   ├─ 1. Policy ──────── permitted at all?        → deny, and record the denial
   │                     (allowlists, per-operation
   │                      gates, volume ceiling)
   │
   ├─ 2. Detection ───── what does this look like  → signals, with weights
   │                     in context?               (8 behavioural detectors)
   │
   ├─ 3. Risk ────────── signals + this actor's     → allow / flag / throttle / deny
   │                     decayed recent history
   │
   └─ 4. Audit ───────── hash-chained record of what was asked,
                         what was decided, and what happened
```

**Risk can narrow what policy permits. It can never widen it.** A policy
denial is final regardless of how low the risk score is, and no threshold
setting can make a forbidden call allowed. If that relationship were
bidirectional, tuning a number would be a way to grant permissions, and the
allowlist would stop being the authority on what is allowed.

### 1. Policy — the preventive layer

Default deny. An empty `ALLOWED_MODELS` permits nothing, so every widening is
something a human typed.

Read, write and delete are separate gates. Being allowed to read `res.partner`
does not imply writing it; being allowed to write does not imply deleting.
Most agent integrations need to read broadly and write narrowly, and a single
"allowed models" list cannot express that.

`execute_method` — arbitrary method on arbitrary model, the widest surface in
any Odoo API wrapper — is off by default, takes a method allowlist, and
refuses the ORM write primitives outright. Calling `unlink` through it would
otherwise delete records while never touching the delete gate.

Credential fields are matched by pattern, so the ones modules add under
compound names (`stripe_secret_key`, `unsplash_access_key`, `signup_token`)
are caught too, including on models installed after the server was
configured. They are refused on every model, always. `SENSITIVE_FIELDS` adds
patterns; it cannot remove the built-in floor (`*password*`, `*secret*`,
`*token*`, `*api_key*`, `*apikey*`, `*private_key*`).

The denylist wins over any allowlist, `*` included. Besides the models that
run code or hold credentials directly, it covers the indirect routes:
`res.config.settings`, which reads and writes `ir.config_parameter` on your
behalf, and module install and uninstall. Attachment *content* is only served
by `get_attachment`, which checks the record the file belongs to; the generic
read tools refuse it and leave it out. Reads with no field list also skip
binary fields, so a contact does not arrive with ten copies of its photo.

### 2. Detection — the behavioural layer

Eight detectors, each looking for something a legitimate integration does once
and almost never does repeatedly:

| Detector | What it catches |
|---|---|
| `allowlist_probing` | Repeated denied calls, especially spread across models — the shape of someone mapping what is reachable. Weighted highest: it has no benign high-volume explanation. |
| `delete_burst` | Several deletes in quick succession. A loop that lost its exit condition, or an injected instruction being carried out. |
| `mass_read` | Large cumulative read volume. Each call is under the per-call cap and perfectly legal; only the sum reveals exfiltration. |
| `write_amplification` | One call writing or deleting a batch far above routine, but below the hard cap. |
| `rate_anomaly` | Volume spikes, both absolute and relative to this actor's own baseline. The relative check is what catches a quiet actor suddenly getting busy. |
| `repeated_errors` | A run of failures — an agent guessing at schema it does not have. |
| `privilege_drift` | An established actor touching a model it never has before. |
| `off_hours` | Activity outside the configured window. Weighted low on purpose. |

Detectors describe; they never decide. Each emits weighted signals and the
engine applies the thresholds. A heuristic that can refuse a call on its own
is a heuristic that can take down production by itself — and relatedly, a
detector that crashes is dropped with a note in the log rather than failing
the call, because a bug in statistical code should not be an outage.

Each detector's docstring states how it produces **false positives**. A
detector whose failure mode you cannot describe is one you will end up
ignoring in practice. The defaults are tuned to start noisy and be tightened
against real traffic, rather than start silent and hope.

### 3. Risk — turning signals into a decision

The score combines the current call's signals with the actor's recent ones,
discounted by an exponential half-life (15 minutes by default). Patterns worth catching are
built from individually unremarkable calls — the third delete is only alarming
because of the first two — so history has to count. It has to decay just as
much, or an actor that tripped a detector once is permanently degraded and the
operator switches governance off.

Two kinds of signal are counted differently. A delete burst or an oversized
write is *new evidence* each time, so those add up: three deletes in a minute
score 25, the fourth 50, the fifth 75 and is refused. Off-hours, a high call
rate, an unfamiliar model or a run of errors describe a *state* that every
call in it reports again; those count once, at their strongest decayed
weight. Summing them was how an ordinary assistant session used to get
blocked within minutes. Calls refused because of risk do not feed the score
that refused them, so an agent that keeps retrying still cools off, and the
score is capped at 100.

Scoring is per-actor: one misbehaving agent does not raise another's risk.

| Score | Decision |
|---|---|
| below throttle | `allow`, or `allow_flagged` if anything fired |
| ≥ `RISK_THROTTLE_THRESHOLD` | `throttle` — the call succeeds after a real delay, turning a runaway loop into a trickle so a human has time to notice |
| ≥ `RISK_BLOCK_THRESHOLD` | `deny` |

### 4. Audit — the forensic layer

An append-only SQLite log where each event stores the hash of the one before
it, so every hash depends on the entire history.

**What the log deliberately does not contain:** argument values. Odoo records
hold personal and commercial data, and an audit log is the wrong place to
accumulate a second copy of it. Stored instead are field *names* (useful, not
sensitive) and a SHA-256 digest of the arguments, which lets you prove two
calls were identical without being able to read either.

Each event does record the *ids* a call created, changed or deleted, as part
of the hashed chain — "which record?" is the first question after an
incident.

Denials are recorded, not dropped. A refusal is evidence, and the probing
detector is built entirely out of refusals.

The values live somewhere else on purpose: the **change journal**
(`data/changes.db`, `0600`, `CHANGE_JOURNAL`) keeps the old and new values of
every create, write and delete, linked to the audit event that sealed it, with
credential fields stripped. The panel shows it under *Changes*. Keeping it
separate means the audit log can be handed to an investigator without handing
over the ERP.

#### Threat model, stated plainly

This is where most "tamper-proof log" claims quietly overreach.

- **Detected.** Editing, deleting, reordering or splicing in a past event. The
  chain breaks at a named sequence number. Repairing the hash of the row you
  edited does not help — the next event still commits to the old one, so the
  break just moves forward one.
- **Detected only with `AUDIT_HMAC_KEY` set.** An attacker who can read and
  write the database file and knows the record format can, with a plain
  SHA-256 chain, recompute every hash from the altered point forward and
  produce a chain that verifies. An HMAC chain closes this off for anyone who
  has the file but not the key.
- **Not detected by this module alone.** An attacker who owns the running
  process has the key and can rewrite everything, head included. No
  single-host design fixes that. The answer is anchoring: periodically copy
  the head hash somewhere the server cannot reach back into. `AuditLog.anchor`
  exists for this and it is a two-line cron job, not a product.
- **Also not detected.** Anything that bypasses this server and talks to Odoo
  directly. Governance here covers the MCP surface; claiming more would be
  dishonest.

**Known limitation.** The audit event is written once, after the outcome is
known. If the process dies mid-call, the attempt leaves no trace. Recording
intent before and outcome after would close that gap at the cost of doubling
the log; for now the single event wins, and startup self-check verifies the
log is writable so the common failure is caught before it matters.

## Running it

### Claude Desktop (stdio)

```json
{
  "mcpServers": {
    "odoo": {
      "command": "odoo-mcp-governed",
      "args": ["stdio"],
      "env": {
        "ODOO_URL": "https://erp.example.com",
        "ODOO_DB": "mydb",
        "ODOO_USERNAME": "bot@example.com",
        "ODOO_API_KEY": "…",
        "ODOO_ENVIRONMENT": "staging",
        "ALLOWED_MODELS": "res.partner,sale.order",
        "AUDIT_HMAC_KEY": "…",
        "DATA_DIR": "/home/me/.local/share/odoo-mcp-governed"
      }
    }
  }
}
```

### HTTP, with the admin panel

```bash
cp .env.example .env && chmod 600 .env    # fill in JWT_SECRET, ADMIN_PASSWORD, AUDIT_HMAC_KEY
mkdir -m 700 -p data
docker compose up -d                       # listens on 127.0.0.1:8020
odoo-mcp-governed token --actor claude     # one token per agent
```

The MCP endpoint is `POST /mcp` (`POST /` also works). The admin panel at
`/admin` manages Odoo profiles (switching is instant, no restart), edits the
policy live — tools on/off, model lists, `execute_method` — shows the token,
and has an audit view with filters and a per-actor risk table. It contains no
JavaScript at all and is served under a CSP that forbids scripts.

Administrative actions — logins, profile switches, policy changes — go into
the same hash chain as agent calls. They are recorded but never risk-scored:
an administrator switching a tool off at 03:00 during an incident must not be
locked out by off-hours signals.

### Command line

```bash
odoo-mcp-governed audit verify   # exit 1 if the chain is broken — cron it
odoo-mcp-governed audit anchor   # append the head hash to data/anchors.log
odoo-mcp-governed token --actor wabot --var partner=42 --hours 2   # registered, scoped
odoo-mcp-governed revoke --actor wabot   # refuse every token of one agent, no restart
odoo-mcp-governed totp-setup     # writes data/totp-setup.txt (0600): secret + otpauth:// URI
```

## Production safeguards

Pointing a development setup at the live ERP is the most ordinary way to lose
data, so there are two independent guards:

- **Unlabelled means production, and production is read-only.** Every profile
  carries an `environment`. A profile without one — typically copied in from
  another tool — is treated as `production`, where creating, writing,
  deleting and `execute_method` are refused at the policy layer. Writing to a
  test database requires labelling it `development` or `staging`; writing to
  production requires ticking `allow writes` on that one profile, which the
  panel then shows in red.
- **`PROTECTED_HOSTS`** lists hosts the server must never contact. A profile
  pointing at one (or any subdomain) cannot be saved or activated, and if the
  active profile turns out to point at one, the server starts with no profile
  rather than connect.
- **The policy is not the only barrier.** A production profile whose Odoo user
  has Settings access — or whose access cannot be verified — refuses `*`
  model lists: if a policy rule were ever missing, nothing in Odoo would stop
  the agent. `server_status` warns about such a user on any profile, and
  reports `writes_enabled` with a plain-language note instead of raw flags.

### Access levels

Each profile has one level:

| Level | For | Reaches | Never |
|---|---|---|---|
| **business** (default) | Agents that work with the business: sales, collections, support, analysis | Business models in the lists; `*` means every *business* model | System models (`ir.*`, users, groups, settings, modules, payment providers…) unless named exactly |
| **sandbox** | Test data and controlled activities | Business models without lists; risk observed only | System models; the denylist |
| **configurator** | A consulting agent setting Odoo up for a client | The whole system: modules, settings, users, groups, views, automations | API keys, `ir.attachment` through the generic tools, credential fields, secret-looking system parameter values. Installing or removing modules and adding code wait for a human |

Sandbox and configurator are refused on production profiles. Files are listed
per record with `list_attachments` and fetched with `get_attachment`, both
checked against the record they belong to; keys and certificates are never
handed out, whatever they belong to.

### A least-privilege production profile

The MCP policy and Odoo's own access control should each be enough on their
own. For production:

| Layer | Setting |
|---|---|
| Odoo user | A dedicated user (for example `mcp_agent`) with an API key, only the groups of the apps the agent works with, and **neither Settings nor Technical** |
| Models | Explicit `ALLOWED_MODELS` and `WRITABLE_MODELS`; `DELETABLE_MODELS` empty unless needed |
| Methods | `ALLOW_EXECUTE_METHOD` off, or a closed `EXECUTE_METHOD_ALLOWLIST` such as `action_confirm,message_post` |
| Denylist | Kept as the floor, not relied on as the main control |
| Secrets | A fresh `JWT_SECRET` (rotating it revokes every token) and `AUDIT_HMAC_KEY` |
| Tokens | One per agent from the Agents page, then `REQUIRE_REGISTERED_TOKENS=true` |
| Several Odoo | Pin every agent to its profile, then `REQUIRE_PINNED_PROFILE=true`: an unpinned agent is refused instead of following the active profile |
| Panel | `ADMIN_TOTP_SECRET` set, HTTPS in front |

## Hardening carried over from day one

`/docs` and the OpenAPI schema are not served. Bodies are capped by counting
bytes, so chunked uploads are capped too. 500s carry no detail. Security
headers on every response, HSTS in HTTPS mode. `Mcp-Session-Id` is validated,
never reflected. `/mcp` is rate-limited per actor, with a per-IP ceiling
before authentication and a separate limit on failed authentications; batches
are capped and every message in one counts. A foreign `Origin` header is
refused (DNS rebinding). `/health` and login are limited per client IP, with
`X-Forwarded-For` honoured only from configured proxies. Credentials and
the audit database are written `0600` from the first byte, atomically. TLS to
Odoo is verified by default. The container runs as a non-root UID on a
read-only root filesystem with all capabilities dropped, `no-new-privileges`,
memory/CPU/PID limits and its own network, publishing on `127.0.0.1` only. For
publishing beyond localhost, `deploy/firewall-docker.sh` restricts the port
through the `DOCKER-USER` chain, since Docker bypasses UFW, and
`deploy/egress-docker.sh` stops the container from opening connections to
anything but Odoo — not the internet, not the LAN, not a database on the host.

Full mapping, item by item: [`docs/SECURITY_BASELINE.md`](docs/SECURITY_BASELINE.md).

## Red-teaming it

Unit tests prove each rule; `redteam/` attacks a running server.

- **`redteam/harness.py`** — fixed, repeatable attacks with an expected outcome
  each: the denylist and its indirect routes, credential fields (domains,
  dotted paths, ordering, nested specifications), attachment content,
  wizards and blocked methods, transport limits, probing, the panic switch,
  agent blocking, a delete burst, and the audit chain afterwards. Standard
  library only.
- **`redteam/canaries.py`** — plants random secrets in a disposable Odoo
  where no agent may read them.
- **`redteam/agent.py`** — an adversarial LLM, through any OpenAI-compatible
  API (Groq's free tier by default), told to steal the canaries, mass-delete
  and talk its way past the server. A canary in anything it received is a
  leak and fails the run; its opinion of how it did is not the verdict.
- **`.github/workflows/redteam.yml`** — runs it on GitHub's machines against
  a throwaway Odoo 19 built by `redteam/ci_world.sh`: the harness on every push
  and pull request, the LLM attacker by hand with two model families. Actions
  are pinned by commit SHA and images by digest, with Dependabot proposing
  bumps.

The harness found a denial of service (a flood of bad tokens locked out
valid agents on the same IP) and the canaries found a content leak
(`ir.attachment.index_content`) on their first runs; both are fixed.

## Tests

The suite has 537 tests (`pytest tests/e2e` drives the panel in Chromium with Playwright). The ones that matter are not the
"it records events" kind — they are the adversarial ones:

```bash
python -m pytest tests/ -q
```

- **Tamper-evidence** (`test_audit_chain.py`) reaches past the public API into
  the SQLite file to simulate an attacker with direct database access, because
  going through the public API would prove nothing — it has no way to modify a
  past event. Modification, deletion, hash repair, forged insertion and the
  unkeyed-vs-HMAC distinction are each asserted to be caught, at the right
  sequence number.
- **No permission leakage** (`test_policy.py`) asserts read does not imply
  write, write does not imply delete, and that `unlink` and `write` cannot be
  laundered through `execute_method` even when explicitly allowlisted.
- **Signal, not noise** (`test_detectors.py`) every detector is tested for
  silence on ordinary traffic as well as for firing on its pattern. One test
  runs a realistic workload through all eight and asserts zero signals — if
  that fails, every alert the system raises is noise.
- **The core invariant** (`test_engine.py`) risk cannot widen policy; a
  crashing detector does not fail the call or inflate the score; actors are
  scored independently; a delete burst that starts permitted ends refused.
- **Concurrency is not a bypass** (`test_concurrency.py`) ten deletes fired in
  parallel are judged as ten, not as ten first deletes each seeing an empty
  history. The test was checked by removing the per-actor lock: without it,
  all ten get through.
- **Never reaches Odoo** (`test_tools.py`) tools run against a fake Odoo that
  records every request, so refusals are asserted as "Odoo saw nothing", not
  merely "an error came back".
- **Production stays read-only** (`test_production_guard.py`) and protected
  hosts cannot be activated, whatever the profile file says.
- **HTTP hardening** (`test_http.py`) `alg: none`, expired, wrong-issuer and
  expiry-less tokens; CSRF; chunked oversized bodies; secrets never in HTML;
  markup injected through audit data rendered inert.

The key security tests were mutation-checked — CSRF, the chunked body limit,
secrets kept out of HTML, the domain password oracle and the per-actor lock:
the protection was removed by hand and the test confirmed to fail, so that a
passing test means something.

Tests drive a fake clock rather than real time, since every detector is a
statement about *when* things happened.

## Configuration

See [`.env.example`](.env.example). There are no insecure defaults: the server
refuses to start in HTTP mode without `ADMIN_PASSWORD` and `JWT_SECRET`, TLS
verification toward Odoo is on, and the model allowlist is empty.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[http,dev]"
pytest -q
ruff check src tests
```

A disposable Odoo 19 CE instance for testing (port 65010):

```bash
cd test-env && docker compose up -d
docker compose exec -T web odoo -d govtest -i base \
  --stop-after-init --db_host=db --db_user=odoo --db_password=odoo
```

## Roadmap

- [x] Governance core — policy, detectors, risk scoring, hash-chained audit
- [x] Odoo client (JSON-RPC, real timeouts) and multi-profile hot swap
- [x] The 19 MCP tools, all routed through the engine
- [x] stdio transport (Claude Desktop) and HTTP transport (JWT)
- [x] Admin panel: profiles, live policy, tokens, audit log with risk view
- [x] Production safeguards: read-only by default, protected hosts
- [x] Hardened Docker image and compose file
- [x] Change journal with before and after values
- [x] One-click undo from the change journal
- [x] Panic switch and per-agent block
- [x] Human approval for destructive or bulk operations (panel, webhook, Telegram)
- [x] Live dashboard, threshold console, permissions by app, sandbox profiles
- [x] Activity report per client; tokens pinned to a profile
- [x] Per-profile model lists, with profile tabs in the panel
- [ ] Approve from the phone (Telegram buttons / WhatsApp reply)
- [ ] Two-phase audit (intent before the call, outcome after)
- [x] Agent registry: per-token revocation, per-agent rules and daily quotas
- [x] Record-level scope per agent, filled from signed token variables
- [x] Prompt-injection warning, grouped and standing approvals, TOTP for the panel
- [ ] Signed off-box anchoring (today: `audit anchor` writes a file to ship)

## Provenance

Written from scratch and MIT licensed. No code was copied from any existing
Odoo MCP server. The implementation follows the published Odoo external API
and the Model Context Protocol specification; the feature set and the
security baseline come from the author's own experience running and hardening
an internal Odoo MCP deployment, documented in
[`docs/SECURITY_BASELINE.md`](docs/SECURITY_BASELINE.md).

## License

MIT — see [LICENSE](LICENSE).
