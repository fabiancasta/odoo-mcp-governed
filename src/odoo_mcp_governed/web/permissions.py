"""The visual permissions table: Odoo's models grouped by app.

Models come from the active Odoo's own registry (``ir.model``), so the table
shows exactly what that database has installed. Wizards (transient models) are
left out: an agent works with records, and a wizard is reached through the
record it belongs to. Models nobody has looked at since the last save are
marked "new — not reviewed" and start unticked, so a module installed later
is never allowed by accident.
"""

from __future__ import annotations

from typing import Any

APPS = {
    "res": "Contacts and companies", "product": "Products", "pos": "Point of Sale",
    "account": "Accounting", "stock": "Inventory", "sale": "Sales", "purchase": "Purchase",
    "hr": "Employees", "mail": "Discuss and mail", "crm": "CRM", "project": "Project",
    "website": "Website", "uom": "Units of measure", "calendar": "Calendar",
    "mrp": "Manufacturing", "helpdesk": "Helpdesk", "l10n": "Localisation",
    "payment": "Payments", "ir": "Technical", "base": "Technical", "bus": "Technical",
    "digest": "Technical", "web": "Technical", "iap": "Technical", "auth": "Technical",
}


def app_key(model: str) -> str:
    return model.split(".", 1)[0]


def app_name(key: str) -> str:
    return APPS.get(key, key.replace("_", " ").capitalize())


def group(models: list[dict[str, Any]], query: str = "") -> list[tuple[str, str, list[dict]]]:
    """``[(app_key, app_name, models)]``, apps sorted by name, wizards dropped."""
    q = query.strip().lower()
    groups: dict[str, list[dict]] = {}
    for m in models:
        if m.get("transient"):
            continue
        name = str(m.get("model") or "")
        if not name:
            continue
        label = str(m.get("name") or "")
        if q and q not in name.lower() and q not in label.lower():
            continue
        groups.setdefault(app_key(name), []).append({"model": name, "name": label})
    return sorted(
        ((k, app_name(k), sorted(v, key=lambda m: m["model"])) for k, v in groups.items()),
        key=lambda g: (g[1] == "Technical", g[1].lower()),
    )


def merge(current: frozenset[str], shown: set[str], ticked: set[str]) -> frozenset[str]:
    """Replace the shown part of an explicit list, keep what was not on screen.

    A filtered page must not drop every model the filter hid. ``*`` is not
    carried over: the "allow all" switch decides that on its own.
    """
    return frozenset((set(current) - shown - {"*"}) | (ticked & shown))
