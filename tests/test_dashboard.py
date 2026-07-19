"""Tests for the review dashboard: record reading, search, and the HTTP API.

These exercise the dashboard against a temporary capture.jsonl and a real
loopback server on an ephemeral port — no proxy or live traffic required.
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

import pytest

from llm_firewall import dashboard


def write_capture(tmp_path: Path, records: list[dict]) -> Path:
    path = tmp_path / "capture.jsonl"
    path.write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records),
        encoding="utf-8",
    )
    return path


SAMPLE = [
    {
        "timestamp": 1000.0,
        "request": {"method": "POST", "host": "api.openai.com", "url": "https://api.openai.com/v1/chat"},
        "response": {"status_code": 200},
        "privacy_redactions": 2,
    },
    {
        "timestamp": 1001.0,
        "request": {"method": "GET", "host": "example.com", "url": "https://example.com/ping"},
        "response": {"status_code": 404},
    },
]


def test_iter_records_indexes_and_skips_malformed(tmp_path: Path) -> None:
    path = tmp_path / "capture.jsonl"
    path.write_text(
        json.dumps(SAMPLE[0]) + "\n" + "not json\n" + "\n" + json.dumps(SAMPLE[1]) + "\n",
        encoding="utf-8",
    )
    got = list(dashboard._iter_records(path))
    # Blank lines are skipped without consuming an index; the malformed line
    # still advances the index so ids stay aligned to file line numbers.
    assert [i for i, _ in got] == [0, 3]
    assert got[0][1]["request"]["host"] == "api.openai.com"


def test_iter_records_missing_file(tmp_path: Path) -> None:
    assert list(dashboard._iter_records(tmp_path / "nope.jsonl")) == []


def test_summary_flags_changed_bodies() -> None:
    record = {
        "timestamp": 5.0,
        "request": {"method": "POST", "host": "h", "url": "u", "body_original": "x"},
        "response": {"status_code": 200},
        "privacy_redactions": 1,
    }
    summary = dashboard._summary(7, record)
    assert summary["id"] == 7
    assert summary["request_changed"] is True
    assert summary["response_changed"] is False
    assert summary["redactions"] == 1


def test_matches_host_and_url() -> None:
    summary = {"host": "api.OpenAI.com", "url": "https://api.openai.com/v1/chat"}
    assert dashboard._matches(summary, "openai")
    assert dashboard._matches(summary, "v1/chat")
    assert not dashboard._matches(summary, "anthropic")


@pytest.fixture()
def live_server(tmp_path: Path):
    """A dashboard server bound to an ephemeral port over a sample capture."""
    write_capture(tmp_path, SAMPLE)
    server = dashboard._make_server("127.0.0.1", 0, tmp_path / "capture.jsonl")
    import threading

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()


def get_json(url: str) -> dict:
    with urllib.request.urlopen(url) as resp:
        return json.loads(resp.read())


def test_api_flows_returns_newest_first(live_server: str) -> None:
    data = get_json(live_server + "/api/flows")
    assert data["count"] == 2
    # Newest (highest timestamp / index) first.
    assert data["flows"][0]["host"] == "example.com"
    assert data["flows"][1]["host"] == "api.openai.com"


def test_api_flows_search_filters(live_server: str) -> None:
    data = get_json(live_server + "/api/flows?q=openai")
    assert data["count"] == 1
    assert data["flows"][0]["host"] == "api.openai.com"


def test_api_flow_detail(live_server: str) -> None:
    detail = get_json(live_server + "/api/flows/0")
    assert detail["id"] == 0
    assert detail["request"]["host"] == "api.openai.com"


def test_api_flow_detail_missing(live_server: str) -> None:
    try:
        get_json(live_server + "/api/flows/999")
    except urllib.error.HTTPError as exc:
        assert exc.code == 404
    else:
        raise AssertionError("expected a 404 for an unknown flow id")


def test_cache_skips_oversized_legacy_lines(tmp_path: Path) -> None:
    # A giant pre-capping line (e.g. a base64 video chunk) must be skipped so the
    # dashboard stays responsive instead of choking on it.
    big = {"request": {"method": "GET", "host": "big.example", "url": "u",
                       "body": "A" * (dashboard.MAX_LINE_PARSE + 10)}}
    small = {"request": {"method": "GET", "host": "small.example", "url": "u2"}}
    path = tmp_path / "capture.jsonl"
    path.write_text(
        json.dumps(big) + "\n" + json.dumps(small) + "\n", encoding="utf-8"
    )
    cache = dashboard.SummaryCache(path)
    hosts = [s["host"] for s in cache.summaries()]
    assert hosts == ["small.example"]
    # The skipped line's id has no offset, so its detail is a clean miss.
    assert cache.record(0) is None
    assert cache.record(1)["request"]["host"] == "small.example"


def test_cache_reads_appended_flows_incrementally(tmp_path: Path) -> None:
    path = tmp_path / "capture.jsonl"
    path.write_text(json.dumps(SAMPLE[0]) + "\n", encoding="utf-8")
    cache = dashboard.SummaryCache(path)
    assert len(cache.summaries()) == 1
    # Simulate the proxy appending another flow while the dashboard is open.
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(SAMPLE[1]) + "\n")
    summaries = cache.summaries()
    assert [s["host"] for s in summaries] == ["api.openai.com", "example.com"]


def test_cache_handles_lines_spanning_chunks(tmp_path: Path, monkeypatch) -> None:
    # Force a tiny read granularity so records straddle chunk boundaries — the
    # reassembly must still yield whole records with correct offsets.
    monkeypatch.setattr(dashboard, "_READ_CHUNK", 8)
    write_capture(tmp_path, SAMPLE)
    cache = dashboard.SummaryCache(tmp_path / "capture.jsonl")
    summaries = cache.summaries()
    assert [s["host"] for s in summaries] == ["api.openai.com", "example.com"]
    assert cache.record(0)["request"]["url"] == SAMPLE[0]["request"]["url"]
    assert cache.record(1)["response"]["status_code"] == 404


def test_index_page_served(live_server: str) -> None:
    with urllib.request.urlopen(live_server + "/") as resp:
        body = resp.read().decode("utf-8")
    assert "llm-firewall" in body
    assert resp.headers["Content-Type"].startswith("text/html")
