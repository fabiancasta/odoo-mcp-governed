"""Writing files that hold credentials.

Two properties, both easy to get wrong:

**Mode 0600 from the first byte.** Creating the file and then calling
``chmod`` leaves a window where it is world-readable under the default umask.
The file is created with ``os.open(..., 0o600)`` so it never exists with
wider permissions.

**Atomic replacement.** Write to a temporary file in the same directory, flush
and fsync it, then ``os.replace`` over the target. A crash mid-write leaves
either the old file or the new one, never a truncated profile list that
silently drops every Odoo connection on the next start.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any


def write_private_json(path: str | Path, data: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"

    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=str(target.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, target)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_name)
        raise


def read_json(path: str | Path, default: Any = None) -> Any:
    target = Path(path)
    if not target.exists():
        return default
    with target.open(encoding="utf-8") as handle:
        return json.load(handle)
