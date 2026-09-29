"""Technology -> vulnerability knowledge used by the CVE engine.

Holds a small, curated, min-version/max-version dataset for common
technologies plus helpers to decide whether a detected version range matches.
Live intelligence (CISA KEV, optional NVD) is fetched by
:mod:`~hunterx.intelligence.advisories` and merged into the same table.
"""

from __future__ import annotations

# (tech_lower, min_version, max_version, cve, severity, cvss, kev, description, remediation)
STATIC_VULNDB: list[tuple[str, str, str, str, str, float, bool, str, str]] = [
    ("express", "4.0.0", "4.16.3", "CVE-2017-1000490", "high", 7.7, False,
     "Express.js response header injection via URL-encoded CR/LF in certain versions.",
     "Upgrade Express to >= 4.16.4."),
    ("express", "", "4.13.3", "CVE-2014-6393", "medium", 6.5, False,
     "Express.js open redirect via location header when trust proxy misconfigured.",
     "Upgrade Express and review trust proxy settings."),
    ("django", "", "2.2.27", "CVE-2021-28658", "high", 7.5, False,
     "Django potential DoS in file upload parsing for versions before 2.2.27 (Django 2.2).",
     "Upgrade Django to a patched release."),
    ("apache httpd", "2.4.0", "2.4.48", "CVE-2021-34798", "medium", 6.5, False,
     "Apache HTTP Server mod_proxy 'Accept-Encoding' memory corruption.",
     "Upgrade Apache to >= 2.4.49."),
    ("nginx", "1.20.0", "1.20.1", "CVE-2021-23017", "high", 7.7, True,
     "Nginx off-by-one in resolver (CISA KEV listed) for versions 0.6.18..1.20.0 (1.20.1 fixed).",
     "Upgrade Nginx to a fixed release."),
    ("wordpress", "", "5.7.2", "CVE-2021-24489", "high", 8.8, True,
     "XML-RPC/request smuggling allowing stored XSS (Exploited in the wild).",
     "Upgrade WordPress."),
    ("tomcat", "9.0.0", "9.0.55", "CVE-2022-23181", "high", 7.5, True,
     "Apache Tomcat local privilege escalation via time-based session fixation.",
     "Upgrade Tomcat to >= 9.0.56."),
    ("gitlab", "0.0.0", "13.10.2", "CVE-2021-22214", "medium", 6.5, True,
     "GitLab unauthenticated SSRF in CI job artifact download API.",
     "Upgrade GitLab to 13.10.3+."),
    ("jenkins", "", "2.440.3", "CVE-2024-23897", "high", 9.8, True,
     "Jenkins arbitrary file read via CLI (Exploited in the wild).",
     "Upgrade Jenkins and restrict CLI access."),
]


def match_range(version: str | None, min_v: str, max_v: str) -> bool:
    """Conservative numeric comparison; no version means 'inconclusive' (False)."""
    from ..utils import version_tuple

    if not version or not version.strip():
        return False
    current = version_tuple(version)
    if not current:
        return False
    if min_v and (vmin := version_tuple(min_v)) and current < vmin:
        return False
    if max_v and (vmax := version_tuple(max_v)) and current > vmax:
        return False
    return True


def candidates_for(technology: str, version: str | None) -> list[dict]:
    from .nuclei_templates import template_available

    tech = technology.lower()
    out: list[dict] = []
    for (t, lo, hi, cve, sev, cvss, kev, desc, remed) in STATIC_VULNDB:
        if t != tech:
            continue
        out.append({
            "cve": cve, "severity": sev, "cvss": cvss, "kev": kev,
            "matched": match_range(version, lo, hi),
            "description": desc, "remediation": remed,
            "min_version": lo, "max_version": hi,
            "has_template": template_available(cve),
        })
    return out