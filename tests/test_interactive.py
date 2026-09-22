"""Tests for the interactive scan planner."""

from __future__ import annotations

import pytest

from hunterx.interactive import SCAN_OPTIONS, plan_scan, tier_for_choice


def test_plan_all_selection_runs_every_phase():
    plan = plan_scan(target="crypto.com", profile="safe",
                     selection=list(range(1, len(SCAN_OPTIONS) + 1)),
                     wordlist=None, notify=False)
    # reporting is always appended; notification only when requested.
    assert plan["phases"] == [
        "discovery", "dns", "http", "ports", "fingerprinting",
        "urls", "javascript", "parameters", "fuzzing", "scanners",
        "cve", "dedup", "evidence", "prioritization", "ai", "reporting",
    ]


def test_plan_notification_appended_when_requested():
    plan = plan_scan(target="crypto.com", profile="passive",
                     selection=[1], wordlist=None, notify=True)
    assert plan["phases"][-1] == "notification"


def test_plan_subset_preserves_pipeline_order():
    plan = plan_scan(target="crypto.com", profile="safe",
                     selection=[5, 2], wordlist=None, notify=False)
    # option 5 = scanners, option 2 = http/ports/fingerprinting; ordering
    # follows pipeline PHASES, not selection order.
    assert plan["phases"] == ["http", "ports", "fingerprinting", "scanners", "reporting"]


def test_plan_dedupes_phases():
    plan = plan_scan(target="crypto.com", profile="safe",
                     selection=[1, 1, 2], wordlist=None, notify=False)
    assert plan["phases"].count("discovery") == 1


def test_plan_ignores_out_of_range_selection():
    plan = plan_scan(target="crypto.com", profile="safe",
                     selection=[0, 99], wordlist=None, notify=False)
    assert plan["phases"] == ["reporting"]


def test_tier_for_choice():
    assert tier_for_choice("small") == "small"
    assert tier_for_choice("large") == "large"
    assert tier_for_choice("Discovery/Web-Content/common.txt") == "Discovery/Web-Content/common.txt"
    assert tier_for_choice(None) is None
    assert tier_for_choice("") is None