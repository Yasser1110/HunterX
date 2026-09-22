"""Notification channels (webhook, Discord) with cooldown.

Outbound payloads are built from already-redacted stored evidence. Sending
is best-effort and gated by config ``notifications.channels.*.enabled``.
Cooldown prevents alert fatigue for the same finding within a window.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any

import httpx

from ..context import ScanContext

log = logging.getLogger("hunterx.integrations")

_COOLDOWN: dict[str, float] = {}


def _cooldown_key(finding: dict) -> str:
    raw = "|".join(str(finding.get(k, "")) for k in ("id", "type", "resource", "host", "severity"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _within_cooldown(channel: str, finding: dict, window: float) -> bool:
    key = f"{channel}:{_cooldown_key(finding)}"
    now = time.time()
    if key in _COOLDOWN and now - _COOLDOWN[key] < window:
        return True
    _COOLDOWN[key] = now
    return False


def _payload(finding: dict, run_id: str, target: str) -> dict[str, Any]:
    return {
        "run": run_id,
        "target": target,
        "finding": {
            "id": finding.get("id"),
            "type": finding.get("type"),
            "severity": finding.get("severity"),
            "asset": finding.get("asset"),
            "url": finding.get("url"),
            "confidence": finding.get("confidence"),
            "status": finding.get("status"),
            "source": finding.get("source"),
            "cve": finding.get("cve"),
            "evidence": finding.get("evidence") or {},
        },
        "occurred_at": finding.get("last_seen"),
    }


async def _try_send_http(url: str, payload: dict, headers: dict | None = None) -> bool:
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
        return True
    except Exception as exc:
        log.warning("webhook delivery failed: %s", exc)
        return False


async def send_webhook(ctx: ScanContext, finding: dict, cfg: dict) -> bool:
    if not cfg.get("enabled", False):
        return False
    url = cfg.get("url")
    if not url:
        return False
    if _within_cooldown("webhook", finding, float(cfg.get("cooldown_seconds", 300))):
        return False
    headers = {"X-HunterX-Event": "finding", "X-HunterX-Run": ctx.run_id,
               **cfg.get("headers", {})}
    return await _try_send_http(url, _payload(finding, ctx.run_id, ctx.target), headers)


async def send_discord(ctx: ScanContext, finding: dict, cfg: dict) -> bool:
    if not cfg.get("enabled", False) or not cfg.get("webhook_url"):
        return False
    if _within_cooldown("discord", finding, float(cfg.get("cooldown_seconds", 300))):
        return False
    color = {"critical": 0xC0392B, "high": 0xE67E22, "medium": 0xF1C40F,
             "low": 0x27AE60, "info": 0x2980B9}.get(str(finding.get("severity", "info")).lower(), 0x95A5A6)
    embed = {
        "title": f"[{str(finding.get('severity','info')).upper()}] {finding.get('type', 'finding')}",
        "description": str(finding.get("url") or finding.get("asset", "")),
        "color": color,
        "fields": [
            {"name": "Asset", "value": str(finding.get("asset", ""))[:1000], "inline": True},
            {"name": "Confidence", "value": str(finding.get("confidence", "")), "inline": True},
            {"name": "Status", "value": str(finding.get("status", "")), "inline": True},
            {"name": "CVE", "value": str(finding.get("cve") or "—"), "inline": True},
        ],
        "footer": {"text": f"hunterx run {ctx.run_id} · {ctx.target}"},
    }
    return await _try_send_http(cfg["webhook_url"], {"embeds": [embed]},
                                headers={"Content-Type": "application/json"})


async def notify(ctx: ScanContext, findings: list[dict]) -> int:
    """Dispatch new findings to every enabled channel once. Returns sent count."""
    cfg = ctx.cfg.notifications_cfg()
    channels = cfg.get("channels", {})
    sent = 0
    for finding in findings:
        for name, ccfg in channels.items():
            handler = {"webhook": send_webhook, "discord": send_discord}.get(name)
            if not handler or not ccfg.get("enabled", False):
                continue
            try:
                if await handler(ctx, finding, ccfg):
                    sent += 1
            except Exception as exc:
                log.warning("notification channel %s failed: %s", name, exc)
    log.info("notify: %d notifications dispatched", sent)
    return sent