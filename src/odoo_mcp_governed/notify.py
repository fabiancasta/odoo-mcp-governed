"""Tell a human that an agent is waiting for approval.

Two optional channels: a generic webhook (JSON POST — point it at n8n, Make,
a Twilio/WhatsApp flow or your own endpoint) and Telegram. Messages carry who,
what tool, which model and how many records — never record values — plus the
panel link where the decision is made. Sending happens on a background
thread with a short timeout: a slow or broken channel never delays an agent
call, and a failure is logged rather than raised.

Note: with deploy/egress-docker.sh in place the container cannot reach these
services; allow the webhook's address explicitly if you use one.
"""

from __future__ import annotations

import json
import logging
import threading
import urllib.request
from typing import Any

log = logging.getLogger(__name__)


class Notifier:
    def __init__(
        self,
        *,
        webhook_url: str = "",
        telegram_token: str = "",
        telegram_chat_id: str = "",
        panel_url: str = "",
        background: bool = True,
        timeout: float = 5.0,
    ) -> None:
        self.webhook_url = webhook_url.strip()
        self.telegram_token = telegram_token.strip()
        self.telegram_chat_id = telegram_chat_id.strip()
        self.panel_url = panel_url.rstrip("/")
        self.background = background
        self.timeout = timeout

    @property
    def enabled(self) -> bool:
        return bool(self.webhook_url or (self.telegram_token and self.telegram_chat_id))

    def approval_requested(self, request: dict[str, Any]) -> None:
        if not self.enabled:
            return
        approve_url = f"{self.panel_url}/admin/approvals" if self.panel_url else "/admin/approvals"
        count = request.get("record_count")
        text = (
            f"Approval needed #{request['id']}: agent {request['actor']} wants to run "
            f"{request['tool']} on {request.get('model') or '-'}"
            f"{f' ({count} records)' if count else ''} — profile {request['profile']}. "
            f"Approve or deny: {approve_url}"
        )
        payload = {
            "event": "approval_requested", "request_id": request["id"],
            "actor": request["actor"], "tool": request["tool"], "model": request.get("model"),
            "record_count": count, "profile": request["profile"], "text": text,
            "approve_url": approve_url,
        }
        if self.background:
            threading.Thread(target=self._send, args=(payload,), daemon=True).start()
        else:
            self._send(payload)

    def _send(self, payload: dict[str, Any]) -> None:
        if self.webhook_url:
            self._post(self.webhook_url, payload, "webhook")
        if self.telegram_token and self.telegram_chat_id:
            self._post(
                f"https://api.telegram.org/bot{self.telegram_token}/sendMessage",
                {"chat_id": self.telegram_chat_id, "text": payload["text"]},
                "telegram",
            )

    def _post(self, url: str, body: dict[str, Any], channel: str) -> None:
        request = urllib.request.Request(
            url, data=json.dumps(body).encode(), method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                response.read()
        except Exception as exc:  # noqa: BLE001 - a notification must never break a call
            log.warning("approval notification via %s failed: %s", channel, type(exc).__name__)
