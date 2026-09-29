"""Intelligence: live template updates + a small CVE->template index.

Updating nuclei templates is a network operation; it is gated by config
(``intel.update_nuclei_templates``) and only runs against the public
nuclei repo (which we do not control - the update itself is harmless and
read-only, template RUNNING always stays behind the risk policy in
:mod:`hunterx.scanners.nuclei`).
"""

from __future__ import annotations

import logging

from ..context import ScanContext

log = logging.getLogger("hunterx.intelligence.templates")

# Known mappings CVE -> nuclei template-id (or family) for chatty CVEs we
# match on. Fully heuristic; used only to hint what to run/confirm.
TEMPLATE_INDEX: dict[str, str] = {
    "CVE-2021-24489": "wordpress/plugins/wpdrawattention-cve-2021-24489.yaml",
    "CVE-2021-22214": "http/cves/2021/CVE-2021-22214.yaml",
    "CVE-2024-23897": "http/cves/2024/CVE-2024-23897.yaml",
    "CVE-2021-23017": "http/cves/2021/CVE-2021-23017.yaml",
    "CVE-2017-1000490": "http/cves/2017/CVE-2017-1000490.yaml",
    "CVE-2022-23181": "http/cves/2022/CVE-2022-23181.yaml",
}

# Families under which templates are commonly stored (not exhaustive).
KNOWN_TEMPLATE_FAMILIES = {
    "wordpress", "drupal", "joomla", "apache", "nginx", "grafana", "jenkins",
    "gitlab", "confluence", "exchange", "log4shell", "spring4shell", "tomcat",
}


def template_available(cve: str | None) -> bool:
    if not cve:
        return False
    return cve.upper() in TEMPLATE_INDEX


def template_id_for(cve: str | None) -> str | None:
    if not cve:
        return None
    return TEMPLATE_INDEX.get(cve.upper())


async def update_nuclei_templates(ctx: ScanContext) -> str | None:
    if not ctx.intel_cfg.get("update_nuclei_templates", True):
        log.info("templates: update disabled in config")
        return None
    if not ctx.tools.available("nuclei"):
        log.info("templates: nuclei not installed; skipping template update")
        return None
    result = await ctx.atool("nuclei", ["-update-templates"], timeout=300)
    if result.ok:
        log.info("templates: nuclei templates updated")
        return "templates-updated"
    log.warning("templates: nuclei -update-templates failed (exit %s)", result.exit_code)
    return None