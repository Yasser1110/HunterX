"""Adaptive content discovery (smart fuzzing).

Approach instead of ``host x huge wordlist``:

1. probe a random path to classify wildcard/soft-404 behavior per host,
2. pick a wordlist tier based on profile + observed technology,
3. prefer ``ffuf`` when installed; else an asyncio fallback fuzzer that
   filters using status, size and body-similarity and honors 429 backoff,
4. store found paths; flag dangerous paths as informational findings.

No exploit payloads are ever sent.
"""

from __future__ import annotations

import hashlib
import logging
import random
import time

from ..context import ScanContext
from ..utils import bounded_map, normalize_url
from ..wordlists import load as load_words
from ..wordlists import resolve as resolve_wordlist

log = logging.getLogger("hunterx.web.fuzzing")

DANGEROUS_FINDINGS = {
    ".git/HEAD": "EXPOSED_GIT_DIR",
    ".env": "EXPOSED_ENV_FILE",
    "server-status": "POTENTIAL_AUTH_PASSTHROUGH",
    "phpinfo.php": "PHPINFO_EXPOSED",
    "wp-config.php.bak": "POTENTIAL_BACKUP_FILE",
    "backup.zip": "POTENTIAL_BACKUP_FILE",
    "healtz.txt": "",  # sentinel marker, not a real finding
}


async def _classify_host(ctx: ScanContext, base_url: str) -> dict:
    """Detect wildcard/soft-404 response signatures for a base URL."""
    session = ctx.session_now()
    probe = f"{base_url}/{random.randint(10_000_000, 99_000_000)}-hunterx"
    baseline = await session.fetch(probe, timeout=12, allow_status=set())
    if baseline is None:
        return {"base": base_url, "status": 0, "size": 0, "body_sha": "", "wildcard": False}

    body = baseline.text[:5000] if baseline.text else ""
    sha = hashlib.sha256(body.encode("utf-8")).hexdigest()
    root = await session.fetch(base_url + "/", timeout=12)
    root_body = root.text[:5000] if root and root.text else ""
    soft404 = bool(root) and len(body) > 0 and abs(len(body) - len(root_body)) < 60
    return {
        "base": base_url,
        "status": baseline.status_code,
        "size": len(body),
        "body_sha": sha,
        "wildcard": baseline.status_code == root.status_code if root else False,
        "soft404": soft404,
    }


def _is_significant(candidate: dict, probe_signature: dict) -> bool:
    if candidate["status"] == probe_signature["status"] and (
        candidate["size"] == probe_signature["size"] or candidate["status"] in (301, 302, 401, 403, 500)
    ):
        return False
    return True


async def _fuzz_host_python(ctx: ScanContext, classification: dict, wordlist: list[str],
                            extensions: list[str]) -> list[str]:
    from ..stop import check_stop

    session = ctx.session_now()
    base = classification["base"]
    found: list[str] = []
    concurrency = ctx.profile["concurrency"].get("fuzzing", 10)
    sem = __import__("asyncio").Semaphore(max(1, concurrency))

    async def try_word(word: str) -> str | None:
        check_stop()
        async with sem:
            url = f"{base}/{word.strip('/')}"
            resp = await session.fetch(url, timeout=12)
            if resp is None:
                return None
            body = resp.text[:5000] if resp.text else ""
            size = len(body)
            if not _is_significant({"status": resp.status_code, "size": size}, classification):
                return None
            if classification.get("wildcard") or classification.get("soft404"):
                sha = hashlib.sha256(body.encode("utf-8")).hexdigest()
                if sha == classification["body_sha"]:
                    return None
            found_url = f"{base}/{word.strip('/')}"
            return normalize_url(found_url)

    for chunk_start in range(0, len(wordlist), 400):
        chunk = wordlist[chunk_start : chunk_start + 400]
        outcomes = await bounded_map(chunk, concurrency, try_word, stop=check_stop)
        for word, outcome in zip(chunk, outcomes):
            if outcome and not isinstance(outcome, Exception):
                ctx.store.upsert_url(outcome, source="fuzzing", status_code=None)
                found.append(outcome)
    return found


def _load_wordlist(ctx: ScanContext, tier: str) -> list[str]:
    tiers = ctx.cfg.wordlists_cfg().get("tiers", {})
    over = ctx.cfg.override_wordlist
    ref = tiers[over] if over in tiers else (over or tiers.get(tier))
    base_dir = ctx.cfg.paths.wordlists
    path = resolve_wordlist(base_dir, ref)
    if path is None:
        # small tier generally resolves to common.txt; otherwise fall back.
        path = resolve_wordlist(base_dir, tiers.get("small"))
    return load_words(path)


async def _fuzz_host_ffuf(ctx: ScanContext, classification: dict, wordlist_path: Path,
                          extensions: list[str]) -> list[str]:
    base = classification["base"]
    filters = []
    if classification["size"]:
        filters += ["-fs", str(classification["size"])]
    if classification["status"]:
        filters += ["-fc", str(classification["status"])]
    out_file = ctx.cfg.paths.data / "tool-outputs" / f"ffuf-{abs(hash(base))}.json"
    args = ["-u", f"{base}/FUZZ", "-w", str(wordlist_path),
            "-mc", "200,204,301,302,401,403,500",
            "-o", str(out_file), "-of", "json", "-t", str(ctx.profile["concurrency"].get("fuzzing", 10)),
            "-timeout", "8", *filters]
    result = await ctx.atool("ffuf", args, timeout=900)
    if not result.ok:
        return []
    found: list[str] = []
    try:
        import json as _json
        data = _json.loads(out_file.read_text(encoding="utf-8", errors="replace"))
        for res in data.get("results", []):
            url = res.get("url")
            if url and ctx.scope.is_allowed_url(url):
                ctx.store.upsert_url(normalize_url(url), source="fuzzing")
                found.append(url)
    except Exception:
        pass
    return found


def _tier_for(ctx: ScanContext) -> str:
    return {"passive": "small", "safe": "small", "balanced": "medium", "deep": "large"}.get(
        ctx.profile_name, "medium"
    )


async def run(ctx: ScanContext) -> int:
    if ctx.profile_name == "passive":
        log.info("fuzzing: passive profile - skipping content discovery")
        return 0
    seeds = [f"https://{h}" for h in
             {str(r["fqdn"]) for r in ctx.db.assets() if ctx.scope.is_allowed_host(str(r["fqdn"]))}][:20]
    if not seeds:
        return 0
    live = ["https://" + h for h in seeds if ctx.store.urls(host=h)]
    if not live:
        # fall back to probe hosts by DNS presence
        live = seeds
    classifications = await bounded_map(live, 5, _classify_host)
    tier = _tier_for(ctx)
    wordlist = _load_wordlist(ctx, tier)
    wordlist_path = ctx.cfg.paths.data / "fuzz-active.txt"
    wordlist_path.parent.mkdir(parents=True, exist_ok=True)
    wordlist_path.write_text("\n".join(wordlist), encoding="utf-8")

    total = 0
    ffuf = ctx.tools.available("ffuf")
    for outcome in classifications:
        if isinstance(outcome, Exception):
            continue
        classification = outcome
        if not classification["status"]:
            continue
        if ffuf:
            found = await _fuzz_host_ffuf(ctx, classification, wordlist_path,
                                          ctx.cfg.wordlists_cfg().get("extensions", []))
        else:
            found = await _fuzz_host_python(ctx, classification, wordlist,
                                            ctx.cfg.wordlists_cfg().get("extensions", []))
        total += len(found)
        _flag_dangerous(ctx, classification["base"], found)
        if total >= 2000:
            log.info("fuzzing: hit 2000 found pages cap")
            break
    log.info("fuzzing: %d additional paths discovered (%s tier)", total, tier)
    return total


def _flag_dangerous(ctx: ScanContext, base: str, found: list[str]) -> None:
    for url in found:
        path = url.split("?")[0].rstrip("/")
        for marker, kind in DANGEROUS_FINDINGS.items():
            if not kind:
                continue
            if path.endswith(marker) or f"/{marker}" in path:
                ctx.store.upsert_finding(
                    asset=url.split("/")[2],
                    url=url,
                    type_=kind,
                    severity="low",
                    confidence="potential",
                    source="hunterx-fuzz",
                    status="needs_manual_verification",
                    evidence={"found_path": path,
                              "required": "verify content manually - do not automate download"},
                )
                break