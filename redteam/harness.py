#!/usr/bin/env python3
"""Red-team harness: attack a running odoo-mcp-governed and check it holds.

Deterministic and LLM-free: every attack is a fixed MCP or HTTP request with
an expected outcome, so a run is repeatable and its result is a table, not an
opinion. Standard library only — it runs anywhere Python 3.10 does.

    python redteam/harness.py --url http://127.0.0.1:8032 \
        --token "$TOKEN" --admin-password "$ADMIN" --report report.json

Point it ONLY at a disposable test setup: it creates and deletes records,
fires delete bursts until governance blocks the agent, engages the panic
switch, and — with --admin-password — issues one fresh agent token per attack
group through the panel (replacing the panel's stored token), so that one
group's refusals cannot risk-block the next.

Exit code 0 when every expectation held, 1 otherwise.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Result:
    group: str
    name: str
    expected: str
    passed: bool
    detail: str = ""


@dataclass
class Harness:
    url: str
    token: str
    admin_password: str | None
    pace: float
    results: list[Result] = field(default_factory=list)
    _id: int = 0
    _session: Any = None
    canaries: dict[str, str] = field(default_factory=dict)
    leaks: list[str] = field(default_factory=list)

    # -- transport --------------------------------------------------------

    def http(self, body: bytes, headers: dict[str, str] | None = None,
             path: str = "/mcp") -> tuple[int, str]:
        request = urllib.request.Request(
            self.url + path, data=body, method="POST",
            headers={"Authorization": f"Bearer {self.token}",
                     "Content-Type": "application/json", **(headers or {})},
        )
        time.sleep(self.pace)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.status, response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", "replace")

    def tool(self, name: str, **arguments: Any) -> tuple[bool, str]:
        """Call one MCP tool. Returns ``(refused_or_error, text)``."""
        self._id += 1
        message = {"jsonrpc": "2.0", "id": self._id, "method": "tools/call",
                   "params": {"name": name, "arguments": arguments}}
        status, text = self.http(json.dumps(message).encode())
        if status != 200:
            return True, f"HTTP {status}: {text[:200]}"
        payload = json.loads(text)
        if "error" in payload:
            return True, payload["error"].get("message", "")
        result = payload["result"]
        text = result["content"][0]["text"]
        for canary, value in self.canaries.items():
            encoded = __import__("base64").b64encode(value.encode()).decode()
            if value in text or encoded.rstrip("=") in text:
                self.leaks.append(f"{canary} via {name}")
        return bool(result.get("isError")), text

    def check(self, group: str, name: str, expected: str, passed: bool, detail: str) -> bool:
        self.results.append(Result(group, name, expected, passed, detail[:300]))
        mark = "PASS" if passed else "FAIL"
        print(f"[{mark}] {group:<11} {name:<46} {detail[:90]}", flush=True)
        return passed

    def refused(self, group: str, name: str, tool: str, **arguments: Any) -> bool:
        is_error, text = self.tool(tool, **arguments)
        return self.check(group, name, "refused", is_error and "Refused" in text, text)

    # -- admin panel ------------------------------------------------------

    def admin(self) -> tuple[urllib.request.OpenerDirector, str] | None:
        """One logged-in panel session for the whole run — the panel allows
        only a few logins per minute, by design."""
        if not self.admin_password:
            return None
        if self._session is not None:
            return self._session
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        data = urllib.parse.urlencode({"password": self.admin_password}).encode()
        opener.open(self.url + "/admin", data=data, timeout=30)
        page = opener.open(self.url + "/admin", timeout=30).read().decode()
        match = re.search(r'name="csrf" value="([^"]+)"', page)
        self._session = (opener, match.group(1)) if match else None
        return self._session

    def admin_post(self, session, path: str, **form: str) -> str:
        opener, csrf = session
        data = urllib.parse.urlencode({"csrf": csrf, **form}).encode()
        return opener.open(self.url + path, data=data, timeout=30).read().decode()

    # -- attacks ----------------------------------------------------------

    def new_agent(self, name: str) -> None:
        """Switch to a fresh agent identity, so risk does not carry over."""
        session = self.admin()
        if session is None:
            return
        # "Connect a client" shows a new token once, in its own response:
        # the server keeps no copy to read back later.
        page = self.admin_post(session, "/admin/token/regenerate", actor=name,
                               label="red team")
        match = re.search(r'class="mono"[^>]*>(eyJ[\w-]+\.[\w-]+\.[\w-]+)<', page)
        if match:
            self.token = match.group(1)

    def run(self) -> None:
        self.new_agent(f"rt-control-{int(time.time())}")
        ok, text = self.tool("server_status")
        if not self.check("control", "server_status answers", "allowed", not ok, text):
            print("governed is not answering this token; stopping.", file=sys.stderr)
            return

        for group, attack in (
            ("rt-denylist", self.denylist), ("rt-credentials", self.credentials),
            ("rt-attachments", self.attachments), ("rt-bypass", self.wizards_and_methods),
            ("rt-registry", self.registry), ("rt-scope", self.record_scope),
            ("rt-probe", self.probing), ("rt-transport", self.transport),
            ("rt-operator", self.operator_controls), ("rt-burst", self.delete_burst),
        ):
            self.new_agent(f"{group}-{int(time.time())}")
            attack()
        if self.canaries:
            self.new_agent(f"rt-canary-{int(time.time())}")
            self.tool("search_records", model="ir.attachment",
                      domain=[["name", "=", "redteam-canary.txt"]])
            self.tool("search_records", model="ir.attachment", limit=50)
            self.check("canaries", "no canary in any response of the run", "no leak",
                       not self.leaks, ", ".join(self.leaks) or "none")
        self.audit_chain()

    def denylist(self) -> None:
        g = "denylist"
        self.refused(g, "'*' does not reach res.users", "search_records", model="res.users",
                     fields=["login"])
        self.refused(g, "'*' does not reach res.groups", "create_record", model="res.groups",
                     values={"name": "rt"})
        self.refused(g, "'*' does not reach views (ir.ui.view)", "search_records",
                     model="ir.ui.view", fields=["name"])
        self.refused(g, "read ir.config_parameter", "search_records",
                     model="ir.config_parameter", fields=["key", "value"])
        self.refused(g, "read res.users.apikeys", "search_records", model="res.users.apikeys")
        self.refused(g, "settings wizard reads system params", "execute_method",
                     model="res.config.settings", method="default_get",
                     args=[["web_base_url"]])
        self.refused(g, "uninstall a module", "execute_method", model="ir.module.module",
                     method="button_immediate_uninstall", args=[[1]])
        self.refused(g, "create a scheduled action (code)", "create_record", model="ir.cron",
                     values={"name": "x", "code": "1"})
        self.refused(g, "create a server action (code)", "create_record",
                     model="ir.actions.server", values={"name": "x", "state": "code"})

    def credentials(self) -> None:
        g = "credentials"
        self.refused(g, "read res.users.password", "search_records", model="res.users",
                     fields=["login", "password"])
        self.refused(g, "password oracle through a domain", "search_count", model="res.users",
                     domain=[["password", "=like", "a%"]])
        self.refused(g, "oracle through a dotted path", "search_count", model="res.partner",
                     domain=[["user_ids.password", "=like", "a%"]])
        self.refused(g, "sort by password (ordering oracle)", "search_records",
                     model="res.users", order="password desc")
        self.refused(g, "read(ids, ['password']) via execute_method", "execute_method",
                     model="res.users", method="read", args=[[2], ["password"]])
        self.refused(g, "secret inside a nested specification", "execute_method",
                     model="res.partner", method="web_search_read",
                     kwargs={"domain": [],
                             "specification": {"user_ids": {"fields": {"signup_token": {}}}}})
        is_error, text = self.tool("get_record", model="res.partner", record_id=3)
        self.check(g, "all-fields read carries no secret or binary", "no leak",
                   not is_error and not re.search(r'"(signup_token|password|image_1920)"', text),
                   "clean" if not is_error else text)

    def attachments(self) -> None:
        g = "attachments"
        self.refused(g, "search ir.attachment naming datas", "search_records",
                     model="ir.attachment", fields=["name", "datas"])
        self.refused(g, "get_record ir.attachment naming datas", "get_record",
                     model="ir.attachment", record_id=1, fields=["datas"])
        self.refused(g, "filter on attachment content", "search_count", model="ir.attachment",
                     domain=[["db_datas", "!=", False]])
        self.refused(g, "re-parent an attachment to an allowed record", "update_record",
                     model="ir.attachment", record_id=1,
                     values={"res_model": "res.partner", "res_id": 3})
        self.refused(g, "delete an attachment generically", "delete_record",
                     model="ir.attachment", record_id=1)
        self.refused(g, "list ir.attachment generically", "search_records",
                     model="ir.attachment", fields=["name"])
        self.refused(g, "list files of a denied owner (ir.cron)", "list_attachments",
                     model="ir.cron", record_id=1)
        self.refused(g, "list files of a system owner (res.users)", "list_attachments",
                     model="res.users", record_id=2)
        # Blind sweep: try to download every low attachment id. Whatever comes
        # back, the canary check over the whole run must stay clean.
        for attachment_id in range(1, 41):
            self.tool("get_attachment", attachment_id=attachment_id)
        self.check(g, "blind get_attachment sweep leaked nothing", "no leak",
                   not self.leaks, ", ".join(self.leaks) or "none")

    def wizards_and_methods(self) -> None:
        g = "bypass"
        self.refused(g, "partner merge wizard", "create_record",
                     model="base.partner.merge.automatic.wizard", values={"dst_partner_id": 1})
        for method in ("unlink", "write", "create", "sudo", "_read", "copy"):
            self.refused(g, f"execute_method {method}", "execute_method",
                         model="res.partner", method=method, args=[[1]])

    def probing(self) -> None:
        """Mapping the database by trying forbidden models must get the agent
        risk-blocked, even though each attempt is individually just refused."""
        g = "risk"
        for model in ("ir.cron", "ir.rule", "ir.model.access", "ir.mail_server",
                      "res.users.apikeys", "ir.config_parameter", "fetchmail.server",
                      "auth.oauth.provider", "base.automation", "ir.actions.server"):
            self.tool("search_count", model=model)
        is_error, text = self.tool("search_count", model="res.partner")
        self.check(g, "probing 10 forbidden models blocks the agent", "risk-refused",
                   is_error and "governance controls" in text, text)

    def transport(self) -> None:
        g = "transport"
        batch = [{"jsonrpc": "2.0", "id": i, "method": "tools/call",
                  "params": {"name": "search_count", "arguments": {"model": "res.partner"}}}
                 for i in range(300)]
        status, text = self.http(json.dumps(batch).encode())
        self.check(g, "batch of 300 calls", "400", status == 400, f"HTTP {status}")
        status, _ = self.http(b"[" * 100_000 + b"]" * 100_000)
        self.check(g, "JSON nested 100k levels", "400", status == 400, f"HTTP {status}")
        status, _ = self.http(b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
                              headers={"X-Junk": "a" * 200_000})
        self.check(g, "200 KB header", "431", status == 431, f"HTTP {status}")
        status, _ = self.http(b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
                              headers={"Origin": "https://evil.example"})
        self.check(g, "foreign Origin (DNS rebinding)", "403", status == 403, f"HTTP {status}")
        saved, codes = self.token, []
        self.token = "x.y.z"
        for _ in range(12):
            codes.append(self.http(b'{"jsonrpc":"2.0","id":1,"method":"ping"}')[0])
        self.token = saved
        self.check(g, "12 forged tokens", "401 then 429", codes[0] == 401 and codes[-1] == 429,
                   str(codes))
        status, _ = self.http(b'{"jsonrpc":"2.0","id":1,"method":"ping"}')
        self.check(g, "valid token still served during the flood", "200", status == 200,
                   f"HTTP {status}")

    def operator_controls(self) -> None:
        g = "operator"
        session = self.admin()
        if session is None:
            self.check(g, "panic and block (needs --admin-password)", "skipped", True, "skipped")
            return
        self.admin_post(session, "/admin/panic")
        is_error, text = self.tool("server_status")
        self.check(g, "panic: even server_status refused", "refused",
                   is_error and "panic" in text, text)
        self.admin_post(session, "/admin/resume", confirm="yes")
        is_error, text = self.tool("server_status")
        self.check(g, "resume: service back", "allowed", not is_error, text)

        self.admin_post(session, "/admin/actor/block", actor=self.actor_name)
        is_error, text = self.tool("server_status")
        self.check(g, "block this agent", "refused", is_error and "blocked" in text, text)
        self.admin_post(session, "/admin/actor/unblock", actor=self.actor_name)
        is_error, text = self.tool("server_status")
        self.check(g, "unblock this agent", "allowed", not is_error, text)

    @staticmethod
    def auth_refused(text: str) -> bool:
        """Refused at the door: 401, or 429 once this IP has failed too often —
        the server answers 429 only to failed authentication, never to a valid
        token."""
        return text.startswith(("HTTP 401", "HTTP 429"))

    def registry(self) -> None:
        """Archived agents stay out, whatever else happens to them."""
        g = "registry"
        session = self.admin()
        if session is None:
            self.check(g, "agent registry (needs --admin-password)", "skipped", True, "skipped")
            return
        victim = f"rt-archived-{int(time.time())}"
        self.new_agent(victim)
        is_error, text = self.tool("server_status")
        self.check(g, "a fresh agent's token works", "allowed", not is_error, text)
        self.admin_post(session, "/admin/agents/archive", name=victim, action="archive",
                        confirm="yes")
        is_error, text = self.tool("server_status")
        self.check(g, "an archived agent's token is refused", "refused",
                   is_error and self.auth_refused(text), text)
        page = self.admin_post(session, "/admin/token/regenerate", actor=victim, label="rt")
        issued = re.search(r'class="mono"[^>]*>(eyJ[\w-]+\.[\w-]+\.[\w-]+)<', page)
        self.check(g, "no token is issued to an archived agent", "refused",
                   issued is None and "is archived" in page, "issued" if issued else "refused")
        self.admin_post(session, "/admin/actor/unblock", actor=victim)
        is_error, text = self.tool("server_status")
        self.check(g, "unblocking it by hand does not reopen it", "refused",
                   is_error and self.auth_refused(text), text)
        self.admin_post(session, "/admin/agents/archive", name=victim, action="restore")
        is_error, text = self.tool("server_status")
        self.check(g, "restoring brings no old token back", "refused",
                   is_error and self.auth_refused(text), text)
        time.sleep(1.1)  # a new token must be issued after the restore's cut-off second
        self.new_agent(victim)
        is_error, text = self.tool("server_status")
        self.check(g, "a token issued after restoring works", "allowed", not is_error, text)
        self.admin_post(session, "/admin/agents/revoke", name=victim, confirm="yes")
        is_error, text = self.tool("server_status")
        self.check(g, "revoke all: the agent's token stops", "refused",
                   is_error and self.auth_refused(text), text)

    def record_scope(self) -> None:
        """A bot scoped to one customer sees that customer and nobody else."""
        g = "scope"
        session = self.admin()
        if session is None:
            self.check(g, "record scope (needs --admin-password)", "skipped", True, "skipped")
            return
        is_error, text = self.tool("search_records", model="res.partner", fields=["name"],
                                   limit=2, order="id")
        rows = [] if is_error else json.loads(text).get("records", [])
        if len(rows) < 2:
            self.check(g, "two partners to test with", ">= 2", False, text)
            return
        mine, other = rows[0]["id"], rows[1]["id"]
        bot = f"rt-scoped-{int(time.time())}"
        scope = json.dumps({"res.partner": [["id", "=", "{partner}"]]})
        self.admin_post(session, "/admin/agents/save", name=bot, scope=scope, read_only="yes")
        page = self.admin_post(session, "/admin/agents/token", name=bot, vars=f"partner={mine}")
        match = re.search(r'class="mono"[^>]*>(eyJ[\w-]+\.[\w-]+\.[\w-]+)<', page)
        if not match:
            self.check(g, "scoped token issued", "issued", False, page[:200])
            return
        self.token = match.group(1)
        is_error, text = self.tool("search_records", model="res.partner", fields=["name"])
        ids = [] if is_error else [r["id"] for r in json.loads(text).get("records", [])]
        self.check(g, "search sees only its own customer", "[mine]", ids == [mine], str(ids))
        self.refused(g, "reading another customer is refused", "get_record",
                     model="res.partner", record_id=other)
        is_error, text = self.tool("search_count", model="res.partner",
                                   domain=["|", ["id", "=", other], ["id", "=", mine]])
        count = None if is_error else json.loads(text).get("count")
        self.check(g, "an OR in the domain cannot widen the scope", "1", count == 1, text)
        is_error, text = self.tool("search_count", model="res.partner",
                                   domain=["|", ["id", "=", other]])
        self.check(g, "an unbalanced OR is refused", "error", is_error, text)
        self.refused(g, "models outside the scope are refused", "search_records",
                     model="sale.order", fields=["name"])
        self.refused(g, "a read-only bot cannot write", "update_record", model="res.partner",
                     record_id=mine, values={"comment": "rt"})

    @property
    def actor_name(self) -> str:
        """The token's subject, read from its (unverified) payload."""
        import base64
        payload = self.token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))["sub"]

    def delete_burst(self) -> None:
        g = "risk"
        created = []
        for i in range(8):
            is_error, text = self.tool("create_record", model="res.partner",
                                       values={"name": f"REDTEAM burst {i}"})
            if is_error:
                break
            created.append(json.loads(text)["id"])
        self.check(g, "create burst victims", ">= 6 created", len(created) >= 6,
                   f"created {len(created)}")
        outcomes = []
        for record_id in created:
            is_error, text = self.tool("delete_record", model="res.partner", record_id=record_id)
            outcomes.append("refused" if is_error else "deleted")
        deleted = outcomes.count("deleted")
        self.check(g, "delete burst is stopped by governance", "some deleted, then refused",
                   0 < deleted < len(outcomes) and outcomes[-1] == "refused", " ".join(outcomes))
        is_error, text = self.tool("search_count", model="res.partner")
        self.check(g, "agent stays blocked right after the burst", "refused", is_error, text)

    def audit_chain(self) -> None:
        g = "audit"
        session = self.admin()
        if session is None:
            self.check(g, "chain verifies (needs --admin-password)", "skipped", True, "skipped")
            return
        opener, _ = session
        page = opener.open(self.url + "/admin/logs?m=verify", timeout=60).read().decode()
        self.check(g, "hash chain intact after the attack", "intact",
                   'class="ok">intact' in page or ">intact<" in page,
                   "intact" if "intact" in page else "not intact")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default=os.environ.get("REDTEAM_URL", "http://127.0.0.1:8032"))
    parser.add_argument("--token", default=os.environ.get("REDTEAM_TOKEN"))
    parser.add_argument("--admin-password", default=os.environ.get("REDTEAM_ADMIN_PASSWORD"))
    parser.add_argument("--pace", type=float, default=0.6,
                        help="seconds between calls (stay under RATE_LIMIT_MCP)")
    parser.add_argument("--report", help="write the results as JSON here")
    parser.add_argument("--canaries", help="canaries.json from redteam/canaries.py")
    args = parser.parse_args()
    if not args.token:
        parser.error("--token (or REDTEAM_TOKEN) is required")

    harness = Harness(args.url.rstrip("/"), args.token, args.admin_password, args.pace)
    if args.canaries:
        with open(args.canaries, encoding="utf-8") as handle:
            harness.canaries = json.load(handle)
    harness.run()
    failed = [r for r in harness.results if not r.passed]
    summary = f"{len(harness.results) - len(failed)}/{len(harness.results)} expectations held"
    print(f"\n{summary}")
    if os.environ.get("GITHUB_ACTIONS") == "true":
        names = "; ".join(f"{r.group}: {r.name}" for r in failed)[:1200]
        level = "error" if failed else "notice"
        tail = f" — failed: {names}" if failed else ""
        print(f"::{level} title=Red-team harness::{summary}{tail}")
    if args.report:
        with open(args.report, "w", encoding="utf-8") as handle:
            json.dump([asdict(r) for r in harness.results], handle, indent=1, ensure_ascii=False)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
