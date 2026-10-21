"""The admin panel in a real browser, clicked through like a QA tester would.

Skipped unless Playwright is installed (``pip install playwright``) and a
Chromium is available (``playwright install chromium``, or set
``PLAYWRIGHT_CHROMIUM`` to an executable). Run with::

    pytest tests/e2e -q

What it catches that the HTTP tests cannot: navigation that disappears,
links that lead nowhere, scripts blocked by the CSP, forms whose buttons do
not submit what they should, and pages that scroll sideways on a phone.
"""

from __future__ import annotations

import glob
import os
import re
import socket
import threading
import time

import pytest

playwright_api = pytest.importorskip("playwright.sync_api")

from odoo_mcp_governed.governance import Decision, Operation, Outcome, ToolCall  # noqa: E402
from odoo_mcp_governed.governance.agents import AgentRule  # noqa: E402
from odoo_mcp_governed.profiles import Profile  # noqa: E402
from odoo_mcp_governed.runtime import Runtime  # noqa: E402
from odoo_mcp_governed.web.app import create_app  # noqa: E402

from ..test_http import ADMIN, make_settings  # noqa: E402

pytestmark = pytest.mark.e2e


def _chromium() -> str | None:
    explicit = os.environ.get("PLAYWRIGHT_CHROMIUM")
    if explicit:
        return explicit
    found = sorted(glob.glob(os.path.expanduser(
        "~/.cache/ms-playwright/chromium_headless_shell-*/*/chrome-headless-shell")))
    return found[-1] if found else None


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    import uvicorn

    tmp = tmp_path_factory.mktemp("e2e")
    # Each test logs in: the production login limit would lock the suite out.
    runtime = Runtime(make_settings(tmp, odoo_environment="development",
                                    writable_models="res.partner",
                                    rate_limit_login="1000/minute"))
    runtime.save_profile(Profile(name="colombia", url="http://co.invalid", database="co",
                                 username="u", api_key="k", environment="production"),
                         actor="seed")
    runtime.save_agent(AgentRule(name="wabot", read_only=True, note="WhatsApp",
                                 models=frozenset({"res.partner"})), actor="seed")
    for decision, model, reasons in ((Decision.ALLOW, "res.partner", ()),
                                     (Decision.ALLOW, "res.partner", ()),
                                     (Decision.DENY, "res.users", ("system_model: x",)),
                                     (Decision.ALLOW_FLAGGED, "res.partner", ())):
        runtime.audit.record(
            ToolCall(actor="claude", profile="default", tool="search_records",
                     operation=Operation.READ, model=model),
            decision=decision, outcome=Outcome.OK if decision is not Decision.DENY
            else Outcome.DENIED, reasons=reasons)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    config = uvicorn.Config(create_app(runtime), host="127.0.0.1", port=port, log_level="error")
    uv = uvicorn.Server(config)
    thread = threading.Thread(target=uv.run, daemon=True)
    thread.start()
    for _ in range(100):
        if uv.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}", runtime
    uv.should_exit = True
    thread.join(timeout=5)


@pytest.fixture(scope="module")
def browser():
    exe = _chromium()
    with playwright_api.sync_playwright() as p:
        try:
            b = p.chromium.launch(executable_path=exe) if exe else p.chromium.launch()
        except Exception as exc:  # noqa: BLE001 - no browser on this machine
            pytest.skip(f"no Chromium for Playwright: {exc}")
        yield b
        b.close()


@pytest.fixture
def page(server, browser):
    base, _ = server
    context = browser.new_context()
    pg = context.new_page()
    errors: list[str] = []
    pg.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    pg.on("pageerror", lambda e: errors.append(str(e)))
    pg.on("response", lambda r: errors.append(f"HTTP {r.status} {r.url}")
          if r.status >= 500 else None)
    pg.goto(base + "/admin")
    pg.fill("input[name=password]", ADMIN)
    pg.click("button[type=submit]")
    pg.wait_for_load_state()
    pg.errors = errors
    yield pg
    context.close()


SIDEBAR = ["Agents", "Dashboard", "Approvals", "Audit log", "Changes", "Report",
           "Permissions", "Odoo instances", "Policy & thresholds", "Panel token"]


def test_login_lands_on_agents(page) -> None:
    assert page.url.endswith("/admin/agents")
    assert page.locator("h1").inner_text() == "Agents"


def test_the_sidebar_never_disappears(page) -> None:
    """The bug the owner found: a tab that made the others vanish."""
    for label in SIDEBAR:
        page.locator("aside.side nav a", has_text=label).first.click()
        page.wait_for_load_state()
        assert page.locator("aside.side nav a").count() == len(SIDEBAR), label
        current = page.locator("aside.side nav a[aria-current=page]")
        assert current.count() == 1 and label in current.inner_text(), label
        assert page.locator("h1").count() == 1, label
    assert not page.errors, page.errors


def test_dashboard_numbers_open_their_events(page) -> None:
    page.click("text=Dashboard")
    page.click("a.stat.link:has-text('Blocked')")
    page.wait_for_load_state()
    assert "decision=deny" in page.url
    assert "1 event(s)" in page.locator(".msg").first.inner_text()
    assert not page.errors, page.errors


def test_an_agent_is_managed_from_its_tree(page, server) -> None:
    _, runtime = server
    page.click("aside.side >> text=Agents")
    page.locator("a.card.agent").first.click()
    page.wait_for_load_state()
    assert page.locator(".roster a.on").count() == 1
    # Switch agent from the roster.
    page.locator(".roster a", has_text="wabot").click()
    page.wait_for_load_state()
    assert "name=wabot" in page.url
    # Quick rule: a daily quota.
    page.fill("form.quick input[name=daily_quota]", "77")
    page.click("form.quick button[type=submit]")
    page.wait_for_load_state()
    assert runtime.agents.rule("wabot").daily_quota == 77
    assert "Agent saved" in page.content()
    # + on the model limit.
    page.locator("form.plus input[placeholder='only these models…']").fill("sale.order")
    page.locator("form.plus:has(input[placeholder='only these models…']) button").click()
    page.wait_for_load_state()
    assert "sale.order" in runtime.agents.rule("wabot").models
    # + token, shown once, inside the tree.
    page.locator("form.plus:has(input[name=from_tree]) button").click()
    page.wait_for_load_state()
    assert page.locator("section.issued textarea").input_value().count(".") == 2
    assert page.locator(".roster").count() == 1
    assert not page.errors, page.errors


def test_permissions_tabs_and_plus(page, server) -> None:
    _, runtime = server
    page.click("aside.side >> text=Permissions")
    page.locator(".tabs a", has_text="colombia").click()
    page.wait_for_load_state()
    assert "profile=colombia" in page.url
    assert page.locator(".tabs a").count() >= 3  # the other tabs are still there
    card = page.locator(".card:has-text('Can read')")
    card.locator("input[name=model][type=text]").fill("pos.order")
    card.locator("button[value=add]").click()
    page.wait_for_load_state()
    assert "pos.order" in runtime.engine.policy.config.profile_lists["colombia"][
        "allowed_models"]
    page.click("text=Use the default again")
    page.wait_for_load_state()
    assert "colombia" not in runtime.engine.policy.config.profile_lists
    assert not page.errors, page.errors


@pytest.mark.parametrize("path", ["/admin/agents", "/admin", "/admin/agents/view?name=claude",
                                  "/admin/permissions", "/admin/logs", "/admin/approvals",
                                  "/admin?tab=policy"])
def test_no_sideways_scroll_on_a_phone(page, server, path) -> None:
    base, _ = server
    page.set_viewport_size({"width": 390, "height": 800})
    page.goto(base + path)
    overflow = page.evaluate(
        "document.scrollingElement.scrollWidth - window.innerWidth")
    assert overflow <= 1, f"{path} scrolls {overflow}px sideways"


def test_every_internal_link_answers(page, server) -> None:
    """Every link on every sidebar page leads somewhere that is not an error."""
    base, _ = server
    seen: set[str] = set()
    for label in SIDEBAR:
        page.goto(base + "/admin/agents")
        page.locator("aside.side nav a", has_text=label).first.click()
        page.wait_for_load_state()
        hrefs = page.eval_on_selector_all(
            "a[href^='/']", "els => els.map(e => e.getAttribute('href'))")
        for href in hrefs:
            if href in seen or re.search(r"logout", href):
                continue
            seen.add(href)
            response = page.request.get(base + href)
            assert response.status < 400, f"{href} -> {response.status} (from {label})"
            assert "Administrator login" not in response.text(), f"{href} logged us out"
