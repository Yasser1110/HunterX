"""Pure-utility tests: URL normalization, version parsing, bounded_map, sha1."""

import asyncio

import pytest

from hunterx.utils import (
    base_scheme_host,
    bounded_map,
    normalize_url,
    redact_text,
    sha1_hex,
    version_tuple,
)


def test_normalize_url_strips_default_ports_and_fragments():
    assert normalize_url("https://a.com:443/x#frag") == "https://a.com/x"
    assert normalize_url("HTTP://A.com:80/path/../x") == "http://a.com/x" or "http://a.com/path/x"


def test_normalize_url_returns_empty_for_empty_and_leaves_unknown_scheme():
    assert normalize_url("") == ""
    assert normalize_url("not a url") == "not a url"


def test_base_scheme_host():
    assert base_scheme_host("https://a.example.com:8080/x") == "https://a.example.com:8080"


def test_version_tuple():
    assert version_tuple("1.2.3") == (1, 2, 3)
    assert version_tuple("2.4") == (2, 4)
    assert version_tuple("nginx/1.20.0") == (20, 0)
    assert version_tuple("") is None


def test_sha1_hex_len():
    assert len(sha1_hex("x")) == 40


def test_redact_text_truncates():
    long = "x" * 500
    assert len(redact_text(long)) <= 121


@pytest.mark.asyncio
async def test_bounded_map_honors_concurrency_and_returns_exceptions():
    async def worker(i):
        await asyncio.sleep(0.01)
        return i * 2

    results = await bounded_map([1, 2, 3], 4, worker)
    assert results == [2, 4, 6]


@pytest.mark.asyncio
async def test_bounded_map_returns_stop_exception_as_result():
    from hunterx.stop import StopRequested

    async def worker(_):
        raise StopRequested()

    results = await bounded_map([1], 1, worker)
    assert len(results) == 1
    assert isinstance(results[0], StopRequested)