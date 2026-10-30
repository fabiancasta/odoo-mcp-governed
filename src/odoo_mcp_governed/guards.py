"""Content guards: what governed checks in the data itself, not in the call.

The policy decides *which* models and operations an agent may use. These
guards look at what flows through an allowed call, where four attacks hide
that a model list cannot see:

- **Prompt injection** planted in record text ("ignore previous
  instructions…"), disguised with look-alike letters, full-width forms or
  invisible characters, in English, Spanish, Portuguese or French.
- **Account takeover** through the e-mail of a contact that belongs to a
  user: whoever controls that address can reset the user's password.
- **Reconnaissance** in Odoo's own error messages, which list the groups that
  would grant access.
- **Identity tricks** in a method's context (``uid``, ``su``,
  ``mail_notrack``…), which governed does not let through.

Pure functions, no Odoo access: the tool layer decides when to call them.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

# -- prompt injection ---------------------------------------------------------

INJECTION_PATTERNS = re.compile(
    # English
    r"(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+)?"
    r"(?:previous|prior|above|earlier|system)\s+(?:instructions|rules|prompts?|messages)"
    r"|system\s+(?:override|prompt)|(?:new|updated|real)\s+instructions\s*:"
    r"|you\s+are\s+now\s+(?:an?\s+|the\s+|in\s+)?(?:admin|administrator|root|developer|superuser"
    r"|unrestricted|system|god\s+mode|developer\s+mode|dan)\b"
    r"|act\s+as\s+(?:an?\s+)?(?:admin|administrator|root|developer|superuser)"
    r"|\b(?:call|run|execute|use)\s+(?:delete_record|update_record|create_record|execute_method)\b"
    r"|approve\s+(?:every|all)\b|do\s+not\s+(?:tell|inform)\s+the\s+user"
    r"|<\|?im_start\|?>|<\|?system\|?>|\[/?INST\]|<<\s*SYS\s*>>"
    # Spanish / Portuguese / French
    r"|(?:ignora|olvida|ignore[sz]?|oublie[sz]?|esque[cç]a)\s+(?:(?:todas|todos|las|los|as|les"
    r"|tus|suas|vos|toutes)\s+){0,2}(?:instrucciones|instru[cç][oõ]es|instructions|reglas|regras"
    r"|r[eè]gles)"
    r"(?:\s+(?:anteriores|previas|pr[eé]c[eé]dentes))?"
    r"|(?:nuevas|novas|nouvelles)\s+instru\w+\s*:"
    r"|(?:ahora\s+eres|agora\s+voc[eê]\s+[eé]|tu\s+es\s+maintenant)\s+(?:un\s+|uma?\s+|el\s+|o\s+|l')?"
    r"(?:admin|administrador|administrateur|root)"
    r"|no\s+(?:le\s+)?(?:digas|informes)\s+al\s+usuario|n[aã]o\s+(?:conte|diga)\s+ao\s+usu[aá]rio"
    r"|aprueba\s+(?:todas|todo)\b|aprove\s+todas?\b",
    re.IGNORECASE,
)
# Look-alike letters (Cyrillic and Greek) that slip past the patterns.
CONFUSABLES = str.maketrans("аеорсхуікАЕОРСХУІКΑΒΕΗΙΚΜΝΟΡΤΧΥοαν",
                            "aeopcxyikAEOPCXYIKABEHIKMNOPTXYoav")
INVISIBLE = re.compile("[­​-‏‪-‮⁠-⁤⁦-⁩﻿]")


def normalized(text: str) -> str:
    """The text as the patterns should see it: full-width folded (NFKC),
    invisible characters removed, look-alike letters mapped to Latin."""
    return INVISIBLE.sub("", unicodedata.normalize("NFKC", text)).translate(CONFUSABLES)


def injection_suspect(text: str) -> str | None:
    """A short excerpt of text that addresses an AI, or ``None``."""
    match = INJECTION_PATTERNS.search(normalized(text))
    return match.group(0)[:60] if match else None


# -- account takeover -----------------------------------------------------------

IDENTITY_FIELDS = {"res.partner": frozenset({"email", "email_normalized"})}
"""Fields that, on a record belonging to a user, decide who can reset that
user's password. Never written through MCP when the record is a user's."""


def identity_fields(model: str, values: dict[str, Any]) -> set[str]:
    return set(values) & IDENTITY_FIELDS.get(model, frozenset())


# -- Odoo error messages ----------------------------------------------------------

GROUPS_HINT = re.compile(
    r"\s*(?:This operation is allowed for|Esta operaci[oó]n est[aá] permitida|"
    r"Esta opera[cç][aã]o [eé] permitida|Cette op[eé]ration est autoris[eé]e|"
    r"Diese Operation ist|Questa operazione [eè] consentita).*",
    re.IGNORECASE | re.DOTALL)


def clean_odoo_error(message: str) -> str:
    """The first paragraph of an Odoo error, without the part that says which
    groups would grant access (free reconnaissance for an attacker, in any
    language and sometimes on the same line) and without a traceback."""
    first = str(message).strip().split("\n\n", 1)[0].split("\nTraceback", 1)[0]
    first = GROUPS_HINT.sub("", first)
    lines = [line for line in first.splitlines() if not line.lstrip().startswith("-")]
    return " ".join(lines).strip()[:300] or "Odoo refused the operation."


# -- method context -----------------------------------------------------------------

CONTEXT_ALLOWED = frozenset({"lang", "tz", "active_test", "allowed_company_ids"})
"""Context keys a method call may set. Everything else is refused: ``uid``
or ``su`` claim another identity, ``mail_notrack`` and friends erase the
trace a change leaves in the chatter, ``default_*`` plant values."""


def context_problem(kwargs: dict[str, Any]) -> str | None:
    context = kwargs.get("context")
    if context is None:
        return None
    if not isinstance(context, dict):
        return "'context' must be an object"
    refused = sorted(set(context) - CONTEXT_ALLOWED)
    if refused:
        return (f"context keys {', '.join(map(repr, refused))} are not accepted; allowed: "
                f"{', '.join(sorted(CONTEXT_ALLOWED))}")
    return None


# -- records that belong to other records -------------------------------------------

LINKED_MODELS = {
    "mail.message": "model",
    "mail.mail": "model",
    "mail.scheduled.message": "model",
    "mail.activity": "res_model",
    "mail.followers": "res_model",
    "rating.rating": "res_model",
    "mail.tracking.value": "mail_message_id.model",
    "mail.notification": "mail_message_id.model",
    "mail.message.reaction": "message_id.model",
}
"""Records that belong to another record (chatter, activities, followers,
ratings) and the field naming that record's model. They follow that record's
governance: no message about an invoice to an agent that may not read
invoices. A fixed list, so deciding it never needs Odoo before the policy has
ruled."""
