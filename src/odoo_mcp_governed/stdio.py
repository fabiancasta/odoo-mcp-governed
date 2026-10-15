"""MCP over stdio: newline-delimited JSON-RPC on stdin/stdout.

Stdout carries protocol messages and nothing else — a stray ``print`` would
corrupt the stream — so all logging goes to stderr.

The actor is fixed (``STDIO_ACTOR``) because a stdio server has exactly one
client: whoever launched it. Governance and the audit log still apply in full;
only the HTTP authentication layer is absent, since there is no network to
authenticate across.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import TextIO

from .protocol import PARSE_ERROR, Dispatcher, _error

log = logging.getLogger(__name__)


def serve_stdio(dispatcher: Dispatcher, actor: str, stdin: TextIO | None = None,
                stdout: TextIO | None = None) -> None:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    log.info("stdio transport ready (actor=%s)", actor)
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            response = _error(None, PARSE_ERROR, "parse error")
        else:
            response = dispatcher.handle_payload(payload, actor)
        if response is not None:
            stdout.write(json.dumps(response, ensure_ascii=False, default=str) + "\n")
            stdout.flush()
