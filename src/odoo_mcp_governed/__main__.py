"""Command line entry point.

    odoo-mcp-governed stdio                 # MCP over stdio (Claude Desktop)
    odoo-mcp-governed http                  # MCP over HTTP + admin panel
    odoo-mcp-governed token --actor NAME    # mint a token for one agent
    odoo-mcp-governed audit verify          # verify the hash chain, exit 1 if broken
    odoo-mcp-governed audit anchor          # append the chain head to anchors.log
"""

from __future__ import annotations

import argparse
import logging
import sys

from .config import ConfigError, Settings


def _logging(level: str) -> None:
    # stderr always: on stdio, stdout belongs to the protocol.
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _runtime(settings: Settings):
    from .runtime import Runtime

    runtime = Runtime(settings)
    for warning in runtime.engine.self_check():
        logging.getLogger("odoo_mcp_governed").warning("%s", warning)
    return runtime


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="odoo-mcp-governed")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("stdio", help="serve MCP over stdio")
    http = sub.add_parser("http", help="serve MCP over HTTP with the admin panel")
    http.add_argument("--host")
    http.add_argument("--port", type=int)
    token = sub.add_parser("token", help="issue a bearer token for one agent")
    token.add_argument("--actor", required=True, help="identity recorded in the audit log")
    token.add_argument("--hours", type=int, help="lifetime (default TOKEN_EXPIRY_HOURS)")
    token.add_argument("--profile", help="pin the agent to this Odoo profile (one per client)")
    report = sub.add_parser("report", help="write the activity report as HTML")
    report.add_argument("--days", type=int, default=7)
    report.add_argument("--out", required=True, help="file to write (print it to PDF)")
    report.add_argument("--profile", help="only this profile (one client)")
    audit = sub.add_parser("audit", help="audit log maintenance")
    audit.add_argument("action", choices=["verify", "anchor"])

    args = parser.parse_args(argv)
    command = args.command or "stdio"
    settings = Settings()
    _logging(settings.log_level)

    try:
        if command == "stdio":
            from .protocol import Dispatcher
            from .stdio import serve_stdio

            runtime = _runtime(settings)
            serve_stdio(Dispatcher(runtime), settings.stdio_actor)
            return 0

        if command == "http":
            import uvicorn

            from .web.app import create_app

            settings.require_http_secrets()
            app = create_app(_runtime(settings))
            uvicorn.run(
                app,
                host=args.host or settings.mcp_host,
                port=args.port or settings.mcp_port,
                proxy_headers=True,
                forwarded_allow_ips=settings.forwarded_allow_ips,
                server_header=False,
                log_level=settings.log_level.lower(),
            )
            return 0

        if command == "token":
            from .web.app import ACTOR_NAME
            from .web.auth import issue_token

            settings.require_http_secrets()
            if not ACTOR_NAME.match(args.actor):
                print("actor may contain only A-Z a-z 0-9 _ . @ -", file=sys.stderr)
                return 2
            data = issue_token(settings, args.actor, hours=args.hours, profile=args.profile)
            print(data["token"])
            print(f"# actor={data['actor']} expires={data['expires_at']}", file=sys.stderr)
            return 0

        if command == "report":
            import os

            from . import report as activity
            from .web.views import report_html

            html = report_html(activity.build(_runtime(settings), days=max(1, args.days),
                                              profile=args.profile))
            fd = os.open(args.out, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(html)
            print(f"report written to {args.out}")
            return 0

        if command == "audit":
            from .governance import AuditLog, AuditStore

            log = AuditLog(AuditStore(settings.audit_db), hmac_key=settings.hmac_key())
            if args.action == "verify":
                status = log.verify()
                print(status.summary())
                return 0 if status.intact else 1
            anchor = log.write_anchor(settings.anchors_file)
            print(f"seq={anchor.seq} head={anchor.head_hash}")
            return 0
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
