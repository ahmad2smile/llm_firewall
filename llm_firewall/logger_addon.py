"""mitmproxy addon that logs each intercepted HTTP(S) flow to disk and stdout.

This is the Python equivalent of the shell setup's ``addon/log_xai.py``. It is
loaded by mitmproxy (either via ``run_proxy.py`` or ``mitmdump -s``) and writes
one JSON-lines record per completed request/response, plus one pretty-printed
JSON file per flow, into the capture directory.

Capture directory precedence:
    1. ``XAI_CAPTURE_DIR`` environment variable
    2. ``~/llm-firewall-capture``
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
from pathlib import Path

from mitmproxy import http

logger = logging.getLogger("llm_firewall")

# Bodies larger than this (decoded chars) are not stored in full. Without a cap a
# single YouTube video chunk — megabytes of base64 — bloats capture.jsonl into
# gigabytes and makes the dashboard that reads it unusably slow. Real LLM/API JSON
# is far smaller than this, so it is logged intact; only big or binary payloads
# are replaced with a short marker.
MAX_LOGGED_BODY = 512 * 1024


def _cap_body(text: str | None, is_base64: bool) -> tuple[str | None, bool, bool]:
    """Return (body, is_base64, truncated). Oversized bodies become a marker."""
    if text is None or len(text) <= MAX_LOGGED_BODY:
        return text, is_base64, False
    if is_base64:
        raw_bytes = len(text) * 3 // 4
        return f"<{raw_bytes} bytes binary — not logged>", False, True
    return text[:MAX_LOGGED_BODY] + f"\n… <truncated, {len(text)} chars total>", False, True


def capture_dir() -> Path:
    """Resolve the capture directory (XAI_CAPTURE_DIR, else ~/llm-firewall-capture)."""
    override = os.environ.get("XAI_CAPTURE_DIR")
    base = Path(override) if override else Path.home() / "llm-firewall-capture"
    base.mkdir(parents=True, exist_ok=True)
    return base


class RequestLogger:
    """Logs completed flows as JSON-lines + per-flow JSON files."""

    def __init__(self) -> None:
        self.capture_dir = capture_dir()
        self.jsonl_path = self.capture_dir / "capture.jsonl"
        self.flows_dir = self.capture_dir / "flows"
        self.flows_dir.mkdir(parents=True, exist_ok=True)
        self._count = 0
        # A single long-lived append handle avoids reopening the file on the
        # event-loop thread for every flow (line-buffered so tails stay live).
        self._jsonl = self.jsonl_path.open("a", encoding="utf-8", buffering=1)
        # Flow ids already written, so a flow that fires both response() and
        # error() isn't logged (or counted) twice.
        self._seen: set[str] = set()

    def load(self, loader) -> None:
        logger.info("logging to %s", self.capture_dir)

    def done(self) -> None:
        """mitmproxy shutdown hook: close the log handle."""
        self._jsonl.close()

    # ---- helpers ---------------------------------------------------------

    @staticmethod
    def _headers(message: http.Message) -> list[list[str]]:
        """Header (name, value) pairs preserving order and duplicates.

        ``dict(message.headers)`` collapses repeated header names (Set-Cookie is
        the common case) down to the last value, silently dropping data this
        logging proxy exists to preserve. Iterate the raw fields instead.
        """
        pairs: list[list[str]] = []
        for name, value in message.headers.fields:
            pairs.append(
                [
                    name.decode("latin-1", "replace"),
                    value.decode("latin-1", "replace"),
                ]
            )
        return pairs

    @staticmethod
    def _charset(message: http.Message) -> str | None:
        content_type = message.headers.get("content-type", "")
        for part in content_type.split(";")[1:]:
            key, _, value = part.strip().partition("=")
            if key.strip().lower() == "charset":
                return value.strip().strip('"') or None
        return None

    @classmethod
    def _decode_body(cls, message: http.Message) -> tuple[str | None, bool]:
        """Return (text_or_none, is_base64). Falls back to base64 for binary.

        We deliberately avoid ``message.get_text``: it silently falls back to
        latin-1 when the content-type carries no charset, which "decodes" any
        byte sequence (video, protobuf, ...) into gibberish that never errors.
        Instead we decompress, then only accept a body as text if the declared
        charset (or strict UTF-8) decodes it cleanly; otherwise base64.
        """
        # get_content decompresses (gzip/br/zstd); strict=False returns the raw
        # bytes untouched if decompression fails rather than raising.
        try:
            raw = message.get_content(strict=False)
        except Exception:
            raw = message.raw_content
        raw = raw or b""
        if not raw:
            return None, False

        # Try the declared charset first, then UTF-8 — deduped so a body that
        # declares utf-8 isn't decoded twice.
        encodings: list[str] = []
        for encoding in (cls._charset(message), "utf-8"):
            if encoding and encoding.lower() not in encodings:
                encodings.append(encoding.lower())
        for encoding in encodings:
            try:
                return raw.decode(encoding), False
            except (UnicodeDecodeError, LookupError):
                continue
        return base64.b64encode(raw).decode("ascii"), True

    def _record(self, flow: http.HTTPFlow) -> dict:
        record: dict = {
            "timestamp": time.time(),
            "client": flow.client_conn.peername[0] if flow.client_conn.peername else None,
            "error": str(flow.error) if flow.error else None,
        }
        # Counters left by the privacy addon. For redacted flows the logged
        # request body is what actually went upstream; for BLOCKED flows
        # (privacy_blocked) it is the client's original body, which never left
        # the machine. Responses are logged in their restored form.
        for key in ("privacy_redactions", "privacy_restored", "privacy_blocked"):
            value = flow.metadata.get(key)
            if value is not None:
                record[key] = value
        req = flow.request
        # In the error() hook a flow can arrive before its request was parsed
        # (TLS/connection failures), so flow.request may be None — guard it.
        if req is not None:
            req_text, req_b64, req_trunc = _cap_body(*self._decode_body(req))
            record["request"] = {
                "method": req.method,
                "scheme": req.scheme,
                "host": req.pretty_host,
                "port": req.port,
                "path": req.path,
                "url": req.pretty_url,
                "http_version": req.http_version,
                "headers": self._headers(req),
                "body": req_text,
                "body_is_base64": req_b64,
            }
            if req_trunc:
                record["request"]["body_truncated"] = True
            # Pre-redaction body, present only when the privacy addon changed it.
            # ``body`` is what went upstream; ``body_original`` is what the client
            # sent — the before/after the dashboard renders.
            original = flow.metadata.get("privacy_request_original_body")
            if original is not None:
                capped, _, _ = _cap_body(original, False)
                record["request"]["body_original"] = capped
        if flow.response is not None:
            resp = flow.response
            resp_text, resp_b64, resp_trunc = _cap_body(*self._decode_body(resp))
            record["response"] = {
                "status_code": resp.status_code,
                "reason": resp.reason,
                "http_version": resp.http_version,
                "headers": self._headers(resp),
                "body": resp_text,
                "body_is_base64": resp_b64,
            }
            if resp_trunc:
                record["response"]["body_truncated"] = True
            # Pre-restoration body (still holding placeholders), present only when
            # the privacy addon restored something. ``body`` is what the local app
            # saw; ``body_original`` is what upstream actually returned.
            original = flow.metadata.get("privacy_response_original_body")
            if original is not None:
                capped, _, _ = _cap_body(original, False)
                record["response"]["body_original"] = capped
        return record

    # ---- mitmproxy hooks -------------------------------------------------

    def response(self, flow: http.HTTPFlow) -> None:
        self._write(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        # Still capture flows that errored out (e.g. TLS/connection failures).
        self._write(flow)

    def _write(self, flow: http.HTTPFlow) -> None:
        # response() and error() can both fire for one flow (e.g. a reset during
        # teardown after a full response); log each flow only once.
        if flow.id in self._seen:
            return
        self._seen.add(flow.id)

        record = self._record(flow)
        self._count += 1

        # Append one line to the JSON-lines log via the long-lived handle.
        self._jsonl.write(json.dumps(record, ensure_ascii=False) + "\n")

        # Write a standalone pretty file per flow for easy reading.
        ts = time.strftime("%Y%m%dT%H%M%S", time.localtime(record["timestamp"]))
        req = record.get("request") or {}
        host = req.get("host") or "unknown"
        safe_host = "".join(c if c.isalnum() or c in ".-" else "_" for c in host)
        flow_path = self.flows_dir / f"{ts}_{self._count:05d}_{safe_host}.json"
        flow_path.write_text(
            json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        # Per-flow traffic is intentionally NOT logged to the terminal — browse it
        # in the review dashboard instead (see dashboard.py). Only warnings/errors
        # (e.g. from the privacy filter) still reach the console.


# mitmproxy discovers module-level `addons`.
addons = [RequestLogger()]
