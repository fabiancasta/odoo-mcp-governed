"""odoo-mcp-governed — a governed MCP server for Odoo.

Every tool call passes through three stages:

1. **Policy** (preventive) — is this actor allowed to do this at all?
2. **Detection** (behavioural) — does this call, in the context of what this
   actor has been doing lately, look like something has gone wrong?
3. **Audit** (forensic) — an append-only, hash-chained record of what was
   asked, what was decided, and what happened.

The governance layer is not a wrapper bolted onto the tools; the tools cannot
reach Odoo except through it.
"""

__version__ = "0.4.0"
