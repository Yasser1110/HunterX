"""Technology fingerprinting from response headers, cookies and body markers.

Signatures are deliberately conservative: header matches are high confidence,
body-regex matches are medium, and product name guessing is low. Confidence
drives later CVE correlation (we never overclaim a version).
"""

from __future__ import annotations

import logging
import re
from typing import Any

from ..context import ScanContext
from ..utils import bounded_map

log = logging.getLogger("hunterx.web.fingerprint")

# name -> (confidence, header-regex-or-None, body-regexes, cookie-prefixes)
SIGNATURES: list[dict[str, Any]] = [
    {"name": "Nginx", "header": r"(?i)^nginx/?([\d.]+)?", "body": []},
    {"name": "Apache httpd", "header": r"(?i)apache/?([\d.]+)?", "body": []},
    {"name": "IIS", "header": r"(?i)microsoft-iis/([\d.]+)", "body": []},
    {"name": "cloudflare", "header": r"(?i)cloudflare", "body": []},
    {"name": "WordPress", "header": None, "body": [r"(?i)wp-content", r"(?i)<meta name=\"generator\" content=\"WordPress"]},
    {"name": "Drupal", "header": None, "body": [r"(?i)/sites/default/files", r"(?i)drupal"]},
    {"name": "Joomla", "header": None, "body": [r"(?i)/media/jui/", r"(?i)com_content"]},
    {"name": "Laravel", "header": None, "body": [r"(?i)laravel_session"]},
    {"name": "Django", "header": None, "body": [r"(?i)csrfmiddlewaretoken", r"(?i)__admin"]},
    {"name": "ASP.NET", "header": r"(?i)asp\.net|via:.*microsoft", "body": [r"(?i)__VIEWSTATE", r"(?i)X-AspNet"]},
    {"name": "Express", "header": r"(?i)express", "body": []},
    {"name": "React", "header": None, "body": [r"(?i)_next/static", r"(?i)__NEXT_DATA__"]},
    {"name": "Next.js", "header": "x-powered-by: next.js", "body": [r"(?i)__NEXT_DATA__"]},
    {"name": "Vue", "header": "x-powered-by: vue", "body": [r"(?i)app\.vue", r"(?i)vue@"]},
    {"name": "Angular", "header": "x-powered-by: angular", "body": [r"(?i)ng-version="]},
    {"name": "PHP", "header": "x-powered-by: php", "body": [r"(?i)\.php\b"]},
    {"name": "Node.js", "header": "x-powered-by: node", "body": [r"(?i)process\.env\.NODE"]},
    {"name": "Java", "header": "x-powered-by: servlet", "body": []},
    {"name": "Spring", "header": "x-powered-by: spring", "body": []},
    {"name": "Tomcat", "header": r"(?i)apache-coyote/?([\d.]+)?", "body": []},
    {"name": "Jenkins", "header": "x-jenkins", "body": [r"(?i)/jenkins/", r"(?i)jenkins-session"]},
    {"name": "GitLab", "header": "x-gitlab-meta", "body": [r"(?i)gitlab"]},
    {"name": "Elasticsearch", "header": None, "body": [r"(?i)cluster_name", r"(?i)you know, for search"]},
    {"name": "Kibana", "header": None, "body": [r"(?i)kibana"]},
    {"name": "Grafana", "header": None, "body": [r"(?i)grafana"]},
    {"name": "Swagger UI", "header": None, "body": [r"(?i)swagger-ui", r"(?i)swagger-ui-dist"]},
    {"name": "GraphQL", "header": None, "body": [r"(?i)graphql"]},
]

_VERSION_HINT = re.compile(r"([\d]+\.[\d]+\.[\d]+(?:\.\d+)?|[\d]+\.[\d]+)")


def _version_from(matches: re.Match | None, text: str) -> str | None:
    if matches and matches.group(1):
        candidate = matches.group(1)
        if len(candidate) <= 20:
            return candidate
    m = _VERSION_HINT.search(text)
    return m.group(1) if m else None


def fingerprint_tech(host: str, headers: dict[str, str], body: str) -> list[dict[str, Any]]:
    discovers: list[dict[str, Any]] = []
    header_blob = "\n".join(f"{k}: {v}" for k, v in headers.items())

    for sig in SIGNATURES:
        version: str | None = None
        confidence = "low"
        hit = False
        if sig.get("header"):
            m = re.search(sig["header"], header_blob)
            if m:
                hit = True
                confidence = "high"
                version = _version_from(m, header_blob)
        for regex in sig.get("body", []):
            if re.search(regex, body, re.I):
                hit = True
                if confidence != "high":
                    confidence = "medium"
        if hit:
            discovers.append({"technology": sig["name"], "version": version, "confidence": confidence})
    return discovers


async def _fingerprint_host(ctx: ScanContext, host: str, url: str) -> None:
    session = ctx.session_now()
    resp = await session.fetch(url, allow_status=set(range(400, 600)), timeout=12)
    if resp is None:
        return
    body = ""
    try:
        body = resp.text or ""
    except Exception:
        pass
    headers = {k.lower(): v for k, v in resp.headers.items()}
    found = fingerprint_tech(host, headers, body[:50000])
    for tech in found:
        ctx.store.upsert_technology(host, tech["technology"], version=tech.get("version"),
                                    confidence=tech["confidence"])


async def run(ctx: ScanContext) -> int:
    hosts = [str(r["fqdn"]) for r in ctx.db.assets() if ctx.scope.is_allowed_host(str(r["fqdn"]))]
    urls: list[str] = []
    for h in hosts:
        urls.append(f"https://{h}/")
        urls.append(f"http://{h}/")
    urls = [u for u in urls if ctx.scope.is_allowed_url(u)]

    if not urls:
        log.info("fingerprint: nothing to fingerprint")
        return 0

    in_flight = ctx.profile["concurrency"].get("http", 20)
    await bounded_map(urls, in_flight, lambda u: _fingerprint_host(ctx, u.split("/")[2], u))
    count = ctx.store.technology_count()
    log.info("fingerprint: %d technology claims saved", count)
    return count