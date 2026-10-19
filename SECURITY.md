# Security policy

odoo-mcp-governed sits between AI agents and an ERP, so a flaw in it can mean
an agent reading or changing data it should never reach. Reports are welcome
and taken seriously.

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x (`main`) | Yes |
| 0.1.x | No — upgrade to 0.2 |

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub: **Security → Report a vulnerability** on
this repository. Include:

- what an agent (or an attacker) can do that it should not;
- the smallest request or sequence of tool calls that shows it;
- the version or commit, and the relevant policy settings (`ALLOWED_MODELS`,
  `execute_method`, profile environment…), with secrets removed.

A failing test in the style of `tests/test_bypasses.py` is the most useful
proof, and the fastest to act on.

## What to expect

- An acknowledgement within 5 business days.
- An assessment and, if confirmed, a fix with a regression test. The fix is
  published first; the details follow once users have had a reasonable time to
  upgrade.
- Credit in the release notes, unless you prefer otherwise.

## Scope

In scope: anything that lets an agent get around governance — policy, the
denylist and its indirect routes, credential fields, attachment content,
risk scoring, approvals, the panic switch and agent blocking, pinned tokens —
and anything that weakens authentication, the admin panel, the audit chain or
the change journal.

Out of scope: weaknesses of Odoo itself, deployments that ignore the
production guidance in the README (an Odoo admin user with `*` everywhere,
a published port without TLS, leaked secrets), and denial of service by
sheer volume beyond the documented rate limits.

## Testing safely

Test only against instances you own, ideally a disposable one. The
`redteam/` kit builds exactly that: a throwaway Odoo and a governed server,
attacked by a fixed harness and an adversarial agent, with canary secrets
that make any leak unambiguous. Never test against someone else's ERP or
production data.

## Design principle

This project's security does not depend on its code or tests being secret:
everything is public on purpose. It depends on the secrets of each
installation — `JWT_SECRET`, the admin password, `AUDIT_HMAC_KEY`, the Odoo
credentials — and on running Odoo with a least-privilege user. Keep those
private and rotate them if they are ever exposed.
