"""Intelligence + JS-analysis tests (pure, no network).

Covers the tech-vulndb version matcher, CVE candidate filtering, nuclei
template index, and JS secret redaction/extraction.
"""

import pytest

from hunterx.intelligence.technologies import candidates_for, match_range
from hunterx.intelligence.nuclei_templates import template_available, template_id_for


def test_match_range_numeric():
    assert match_range("4.16.2", "4.0.0", "4.16.3") is True
    assert match_range("4.20.0", "4.0.0", "4.16.3") is False
    assert match_range("", "4.0.0", "4.16.3") is False
    assert match_range("4.1.0", "", "5.0.0") is True


def test_candidates_for_known_tech():
    express = candidates_for("Express", "4.13.0")
    assert any(c["cve"] == "CVE-2017-1000490" and c["matched"] for c in express)
    assert any(c["cve"] == "CVE-2014-6393" and c["matched"] for c in express)
    future = candidates_for("Express", "5.5.5")
    assert not any(c["matched"] for c in future)


def test_candidates_include_template_hint():
    for c in candidates_for("Jenkins", "2.440.0"):
        if c["cve"] == "CVE-2024-23897":
            assert c["has_template"] is True


def test_template_index():
    assert template_available("CVE-2024-23897") is True
    assert template_id_for("cve-2021-24489") is not None
    assert template_available("CVE-0000-00000") is False


def test_js_analysis_extracts_endpoints_and_params():
    from hunterx.web.js_analysis import analyze_js

    body = '''
      const api = "/api/v1/users?token=abc";
      const xhr = new XMLHttpRequest();
      xhr.open("GET", "/internal/health?verbose=1");
      config = { key: "SECRETTOKEN_VALUE_1234567890" };
      //# sourceMappingURL=app.js.map
    '''
    result = analyze_js("https://a.example.com/app.js", body)
    assert any("internal/health" in e for e in result["endpoints"])
    assert "verbose" in result["params"]
    assert result["sourcemap"] == "app.js.map"


def test_js_secret_redaction_never_leaks_raw(tmp_path):
    from hunterx.web.js_analysis import analyze_js

    token = "ghp_AAAAAAAAAAAABBBBBBBBBBBCCCCCCCCCC"
    body = f"const t = '{token}';"
    result = analyze_js("https://a.example.com/app.js", body)
    secrets = result["secrets"]
    assert secrets and secrets[0]["kind"] == "github_token"
    assert token not in secrets[0]["value"]
    assert "*" in secrets[0]["value"]