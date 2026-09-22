"""AI-assisted triage (Phase 11).

Uses an OpenAI-compatible chat-completions endpoint to attach a short risk
assessment + suggested next step to each finding of the current run. The AI
layer is strictly advisory: it never creates or destroys findings, never
escalates POTENTIAL findings to confirmed, and never fails the pipeline. If
it is disabled, has no API key, or the endpoint errors, the phase is a
graceful no-op returning 0.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re

import httpx

from ..context import ScanContext

log = logging.getLogger("hunterx.analysis.ai")

_SYSTEM_PROMPT = (
    "You are a conservative security triage assistant for an authorized "
    "bug-hunting platform. Rank by real-world exploit likelihood and impact. "
    "Findings with status 'needs_manual_verification' or confidence 'low' are "
    "POTENTIAL - phrase them as hypotheses that require manual verification."
    "Never claim a confirmed takeover or exploitation. Respond with ONLY a "
    "JSON object mapping each given finding id to an object with an "
    "\"assessment\" (1-2 sentences) and a \"next_step\" (one short sentence)."
)

_JSON_BLOCK = re.compile(r"\{.*\}", re.S)
_MAX_FINDINGS = 25
_TIMEOUT = httpx.Timeout(60.0, connect=10.0)


def _chat_url(base: str) -> str:
    base = base.rstrip("/")
    if base.endswith("/v1"):
        return base + "/chat/completions"
    return base + "/v1/chat/completions"


def _note_from(value: str | dict) -> str:
    if isinstance(value, dict):
        bits = [value.get("assessment"), value.get("next_step")]
        return " — ".join(str(b) for b in bits if b) or str(value)
    return str(value)


async def run(ctx: ScanContext) -> int:
    ai = ctx.ai_cfg
    if not ai.get("enabled"):
        log.info("ai: disabled in config, skipping")
        return 0

    api_key = os.environ.get(ai.get("api_key_env") or "OPENAI_API_KEY")
    if not api_key:
        log.warning("ai: enabled but no API key in env var %s; skipping (pipeline unaffected)",
                    ai.get("api_key_env") or "OPENAI_API_KEY")
        return 0

    findings = ctx.store.findings(limit=_MAX_FINDINGS)
    if not findings:
        log.info("ai: no findings to analyze")
        return 0

    payload = {
        "findings": [
            {"id": f["id"], "asset": f.get("asset"), "type": f.get("type"),
             "severity": f.get("severity"), "confidence": f.get("confidence"),
             "status": f.get("status"), "url": f.get("url"),
             "evidence": f.get("evidence") or {}}
            for f in findings
        ]
    }
    request = {
        "model": ai.get("model") or "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(payload, default=str)[:9000]},
        ],
        "temperature": 0.2,
        "max_tokens": 2000,
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(_chat_url(str(ai.get("base_url") or "https://api.openai.com/v1")),
                                     json=request, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        log.warning("ai: analysis failed (%s); skipping without pipeline impact", exc)
        return 0

    content = ""
    try:
        content = data.get("choices", [{}])[0].get("message", {}).get("content") or ""
    except (AttributeError, IndexError, TypeError):
        pass

    match = _JSON_BLOCK.search(content)
    if not match:
        log.warning("ai: no parseable JSON returned by model")
        return 0
    try:
        notes = json.loads(match.group(0))
    except json.JSONDecodeError:
        log.warning("ai: returned JSON was not valid")
        return 0
    if not isinstance(notes, dict):
        log.warning("ai: unexpected response shape")
        return 0

    stamped = 0
    for row in findings:
        fid = row["id"]
        note = notes.get(fid, notes.get(str(fid)))
        if not note:
            continue
        ctx.store.set_ai_note(fid, _note_from(note)[:600])
        stamped += 1
    log.info("ai: attached triage notes to %d findings", stamped)
    return stamped