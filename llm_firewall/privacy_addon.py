"""mitmproxy addon that redacts PII from outbound JSON bodies via a local
privacy-filter API and transparently restores it in responses.

For every non-YouTube request carrying a JSON body, the schema files under
``schemas/`` (one field selector per line, e.g. ``messages[].content[].text``)
decide which JSON values are inspected: only the strings those selectors point
at are sent to the privacy-filter API (``POST /v1/filter`` with
``{"text": ..., "threshold": ...}``, answering with byte-offset entity spans).
Detected entities are replaced with placeholders such as ``[EMAIL_1]`` before
the request leaves the machine. A body that matches none of the selectors is
forwarded unfiltered — the selectors are checked only inside the JSON body,
never against headers, the URL, or a non-JSON payload.

The placeholder -> original mapping lives in memory for the lifetime of the
proxy (it grows with the number of distinct entities seen; restart to reset).
Placeholders appearing in a later response are swapped back to the originals,
so local apps see exactly the values they sent — the redaction is invisible on
this side of the wire. Restoration only applies to responses from hosts that
previously received a redacted request, so cached values can never leak into
an unrelated service's traffic. A given (label, value) pair always maps to the
same placeholder within a run, so multi-turn LLM conversations keep referring
to one entity by one placeholder upstream.

Fail-closed by default: if the filter API is unreachable, errors, or a JSON
body cannot be redacted (unparseable, or larger than the redaction limit),
the request is answered locally with a 502 instead of being forwarded
unredacted. Construct with ``fail_open=True`` (CLI: ``--privacy-fail-open``)
to forward instead — with whatever partial redaction succeeded.

Known gaps (see README): WebSocket frames are not filtered (a warning is
logged per connection), and whitespace-free blob strings (base64 images,
tokens) are skipped by heuristic.

Standalone usage with stock mitmproxy (defaults: filter at
http://127.0.0.1:8080/v1/filter, threshold 0.5, fail-closed):

    mitmdump -s llm_firewall/privacy_addon.py -s llm_firewall/logger_addon.py -p 8888
"""

from __future__ import annotations

import asyncio
import bisect
import json
import logging
import re
from http.client import HTTPConnection, HTTPException, HTTPSConnection
from pathlib import Path
from urllib.parse import urlsplit
from xml.sax.saxutils import escape as _saxutils_escape

from mitmproxy import http
from mitmproxy.net.http.headers import parse_content_type

logger = logging.getLogger("llm_firewall")

DEFAULT_FILTER_URL = "http://127.0.0.1:8080/v1/filter"
DEFAULT_THRESHOLD = 0.5

# Directory of schema files. Each file lists one field selector per line (see
# ``_parse_field_selector``); only the JSON values those selectors point at are
# sent to the privacy filter. A request whose body matches none of the
# selectors is forwarded unfiltered.
DEFAULT_SCHEMAS_DIR = Path(__file__).resolve().parent / "schemas"

# Hosts exempt from both redaction and restoration ("all non-YouTube traffic").
YOUTUBE_SUFFIXES = (
    "youtube.com",
    "youtu.be",
    "youtube-nocookie.com",
    "googlevideo.com",
    "ytimg.com",
)
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}

MAX_REQUEST_BYTES = 5 * 1024 * 1024  # bigger JSON bodies follow the fail policy
MAX_RESPONSE_BYTES = 20 * 1024 * 1024
MIN_STRING_LEN = 2
# Whitespace-free strings this long are treated as blobs (base64 images, data
# URIs, tokens) — not prose the filter model can meaningfully scan.
BLOB_MIN_LEN = 2048
FILTER_TIMEOUT = 30.0
FILTER_CONCURRENCY = 4  # parallel in-flight filter calls per proxy

PLACEHOLDER_RE = re.compile(r"\[[A-Z0-9_]+_\d+\]")


class PrivacyFilterError(Exception):
    """The privacy-filter API could not be reached or gave an unusable answer."""


def _split_content_type(header_value: str | None) -> tuple[str, str | None]:
    """Parse a Content-Type header once: ('type/subtype' lowercased, charset)."""
    parsed = parse_content_type(header_value or "")
    if parsed is None:
        return "", None
    main, sub, params = parsed
    return f"{main}/{sub}", params.get("charset")


def _is_json_content_type(base_ct: str) -> bool:
    return base_ct == "application/json" or base_ct.endswith("+json")


def _is_restorable_content_type(base_ct: str) -> bool:
    return (
        _is_json_content_type(base_ct)
        or base_ct.startswith("text/")
        or base_ct in ("application/x-ndjson", "application/xml")
    )


def _json_string_escape(s: str) -> str:
    """Escape ``s`` for insertion inside a JSON string literal."""
    return json.dumps(s, ensure_ascii=False)[1:-1]


def _xml_escape(s: str) -> str:
    """Escape ``s`` for insertion into XML text or attribute content."""
    return _saxutils_escape(s, {'"': "&quot;", "'": "&apos;"})


def _dump_json_for_charset(obj: object, charset: str | None) -> bytes:
    """Serialize ``obj`` so the bytes are valid in the body's declared charset."""
    text = json.dumps(obj, ensure_ascii=False)
    try:
        return text.encode(charset or "utf-8")
    except (LookupError, UnicodeEncodeError):
        # Exotic/undecodable charset: \u-escape everything so ASCII suffices.
        return json.dumps(obj, ensure_ascii=True).encode("ascii")


def _map_strings(obj: object, fn) -> tuple[object, int]:
    """Rebuild a JSON tree applying ``fn(str) -> (new_str, count)`` to values."""
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, list):
        out_list: list[object] = []
        total = 0
        for item in obj:
            new, n = _map_strings(item, fn)
            out_list.append(new)
            total += n
        return out_list, total
    if isinstance(obj, dict):
        out_dict: dict = {}
        total = 0
        for key, value in obj.items():
            new, n = _map_strings(value, fn)
            out_dict[key] = new
            total += n
        return out_dict, total
    return obj, 0


def _iter_json_string_paths(obj: object, path: tuple):
    """Yield ``(path, string)`` for every string value, in ``_rebuild_json_strings`` order.

    ``path`` is the tuple of keys/indices from the root, so the same logical
    field across successive stream frames (e.g. ``('choices', 0, 'delta',
    'content')``) shares a path and can be reassembled on its own — never joined
    to a sibling field (``id``, ``model``) or a different list element.
    """
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            yield from _iter_json_string_paths(item, path + (i,))
    elif isinstance(obj, dict):
        for key, value in obj.items():
            yield from _iter_json_string_paths(value, path + (key,))


def _rebuild_json_strings(obj: object, values) -> object:
    """Rebuild a JSON tree, replacing each string with the next item from ``values``."""
    if isinstance(obj, str):
        return next(values)
    if isinstance(obj, list):
        return [_rebuild_json_strings(item, values) for item in obj]
    if isinstance(obj, dict):
        return {key: _rebuild_json_strings(value, values) for key, value in obj.items()}
    return obj


# Matches a stream frame line and splits off an optional ``data:`` (SSE) prefix
# from its payload; NDJSON lines have no prefix. The payload is JSON when it
# starts with ``{`` or ``[`` and parses — ``data: [DONE]`` and blank lines fail
# this and are passed through untouched.
_STREAM_DATA_RE = re.compile(r"(data:\s*)(.*)$", re.DOTALL)


def _parse_stream_json_line(line: str) -> tuple[str, object] | None:
    """Split a stream line into ``(prefix, json_obj)``, or None if it is not JSON."""
    match = _STREAM_DATA_RE.match(line)
    prefix, payload = (match.group(1), match.group(2)) if match else ("", line)
    if payload.lstrip()[:1] not in ("{", "["):
        return None
    try:
        return prefix, json.loads(payload)
    except ValueError:
        return None


# ---- schema field selectors ---------------------------------------------
#
# A selector is a dotted path into a JSON *object*, written one per line in a
# schema file. A segment ending in ``[]`` means "the value here is a list;
# descend into each item". The final segment (no ``[]``) names the string
# value(s) to redact. Example: ``messages[].content[].text`` selects the
# ``text`` string inside every item of every message's ``content`` list.


def _parse_field_selector(line: str) -> list[tuple[str, bool]] | None:
    """Parse one selector line into ``[(key, is_list), ...]`` steps, or None.

    Returns None for a malformed line (empty segment, stray brackets) so the
    caller can skip and warn rather than silently mis-selecting fields.
    """
    steps: list[tuple[str, bool]] = []
    for raw in line.split("."):
        seg = raw.strip()
        is_list = seg.endswith("[]")
        key = seg[:-2] if is_list else seg
        if not key or "[" in key or "]" in key:
            return None
        steps.append((key, is_list))
    return steps or None


def _build_selector_trie(selectors: list[list[tuple[str, bool]]]) -> dict:
    """Merge parsed selectors into a trie keyed by field name.

    Each node maps a key to an edge ``{is_list, terminal, children}``; several
    selectors sharing a prefix walk the JSON tree in a single pass.
    """
    root: dict = {}
    for steps in selectors:
        node = root
        for i, (key, is_list) in enumerate(steps):
            edge = node.get(key)
            if edge is None:
                edge = {"is_list": is_list, "terminal": False, "children": {}}
                node[key] = edge
            else:
                edge["is_list"] = edge["is_list"] or is_list
            if i == len(steps) - 1:
                edge["terminal"] = True
            node = edge["children"]
    return root


def _iter_selected(obj: object, trie: dict):
    """Yield every string value in ``obj`` selected by ``trie``."""
    if not trie or not isinstance(obj, dict):
        return
    for key, edge in trie.items():
        if key not in obj:
            continue
        value = obj[key]
        items = value if (edge["is_list"] and isinstance(value, list)) else [value]
        for item in items:
            if edge["terminal"] and isinstance(item, str):
                yield item
            elif edge["children"] and isinstance(item, dict):
                yield from _iter_selected(item, edge["children"])


def _map_selected(obj: object, trie: dict, fn) -> tuple[object, int]:
    """Rebuild ``obj`` applying ``fn(str) -> (new_str, count)`` to selected strings."""
    if not trie or not isinstance(obj, dict):
        return obj, 0
    out: dict = dict(obj)
    total = 0
    for key, edge in trie.items():
        if key not in obj:
            continue
        value = obj[key]
        if edge["is_list"] and isinstance(value, list):
            new_list: list[object] = []
            for item in value:
                new_item, n = _map_selected_item(item, edge, fn)
                new_list.append(new_item)
                total += n
            out[key] = new_list
        else:
            out[key], n = _map_selected_item(value, edge, fn)
            total += n
    return out, total


def _map_selected_item(item: object, edge: dict, fn) -> tuple[object, int]:
    if isinstance(item, str):
        return fn(item) if edge["terminal"] else (item, 0)
    if edge["children"] and isinstance(item, dict):
        return _map_selected(item, edge["children"], fn)
    return item, 0


def _load_field_selectors(schemas_dir) -> list[list[tuple[str, bool]]]:
    """Read every schema file in ``schemas_dir`` into a de-duplicated selector list.

    Blank lines and ``#`` comments are ignored; malformed selectors are skipped
    with a warning. A missing directory yields an empty list (nothing filtered).
    """
    directory = Path(schemas_dir)
    if not directory.is_dir():
        logger.warning(
            "privacy filter: schema directory %s not found; no request fields "
            "will be filtered until it exists",
            directory,
        )
        return []
    selectors: list[list[tuple[str, bool]]] = []
    seen: set[tuple[tuple[str, bool], ...]] = set()
    for path in sorted(directory.iterdir()):
        if not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            logger.warning("privacy filter: cannot read schema %s (%s)", path, exc)
            continue
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            steps = _parse_field_selector(line)
            if steps is None:
                logger.warning(
                    "privacy filter: ignoring invalid field selector %r in %s",
                    line,
                    path.name,
                )
                continue
            key = tuple(steps)
            if key not in seen:
                seen.add(key)
                selectors.append(steps)
    return selectors


class EntityCache:
    """Run-lifetime bidirectional map between originals and placeholders.

    Only touched from the event-loop thread, with no ``await`` between lookup
    and insert, so plain dicts are race-free.
    """

    def __init__(self) -> None:
        self._by_key: dict[tuple[str, str], str] = {}
        self._by_placeholder: dict[str, str] = {}
        self._counters: dict[str, int] = {}

    def __len__(self) -> int:
        return len(self._by_placeholder)

    def placeholder(self, label: str, original: str) -> str:
        """Stable placeholder for this (label, original) pair, e.g. ``[EMAIL_1]``."""
        slug = re.sub(r"[^A-Z0-9]+", "_", (label or "entity").upper()).strip("_") or "ENTITY"
        key = (slug, original)
        ph = self._by_key.get(key)
        if ph is None:
            self._counters[slug] = self._counters.get(slug, 0) + 1
            ph = f"[{slug}_{self._counters[slug]}]"
            self._by_key[key] = ph
            self._by_placeholder[ph] = original
        return ph

    def restore_text(self, text: str, escape=None) -> tuple[str, int]:
        """Swap known placeholders back to originals; unknown ones are left as-is."""
        count = 0

        def swap(match: re.Match[str]) -> str:
            nonlocal count
            original = self._by_placeholder.get(match.group(0))
            if original is None:
                return match.group(0)
            count += 1
            return escape(original) if escape else original

        return PLACEHOLDER_RE.sub(swap, text), count

    def restore_segments(self, segments: list[str]) -> tuple[list[str], int]:
        """Restore placeholders that may span a *sequence* of string segments.

        The segments are concatenated, matched against the cache as one text,
        and rebuilt — so a placeholder streamed in pieces across frames (e.g.
        ``[`` in one SSE delta and ``OCCUPATION_10]`` in the next) is still
        recognised. Each restored value is attributed to the segment that held
        the placeholder's opening ``[``; the overlapped tail segments simply
        drop their share. Unknown placeholders are left untouched.

        Runs in O(total length) — it copies whole slices between matches rather
        than character by character, so a multi-megabyte segment costs a memcpy,
        not a quadratic rebuild on the proxy's event loop.
        """
        buffer = "".join(segments)
        matches = [
            m
            for m in PLACEHOLDER_RE.finditer(buffer)
            if self._by_placeholder.get(m.group(0)) is not None
        ]
        if not matches:
            return list(segments), 0
        # Start offset of each segment in the buffer, for mapping a match back to
        # the segment(s) it covers.
        starts: list[int] = []
        offset = 0
        for seg in segments:
            starts.append(offset)
            offset += len(seg)
        parts: list[list[str]] = [[] for _ in segments]

        def emit(lo: int, hi: int) -> None:
            """Copy ``buffer[lo:hi]`` into the segments that own that range."""
            while lo < hi:
                idx = bisect.bisect_right(starts, lo) - 1
                seg_end = starts[idx] + len(segments[idx])
                end = min(hi, seg_end)
                parts[idx].append(buffer[lo:end])
                lo = end

        cursor = 0
        for match in matches:
            emit(cursor, match.start())
            owner = bisect.bisect_right(starts, match.start()) - 1
            parts[owner].append(self._by_placeholder[match.group(0)])
            cursor = match.end()
        emit(cursor, len(buffer))
        return ["".join(part) for part in parts], len(matches)


class PrivacyFilter:
    """Redact PII in outbound JSON bodies; restore it in response bodies."""

    def __init__(
        self,
        filter_url: str = DEFAULT_FILTER_URL,
        threshold: float = DEFAULT_THRESHOLD,
        fail_open: bool = False,
        schemas_dir=None,
    ) -> None:
        parts = urlsplit(filter_url)
        self.filter_url = filter_url
        self.filter_scheme = (parts.scheme or "http").lower()
        self.filter_host = parts.hostname or "127.0.0.1"
        self.filter_port = parts.port or (443 if self.filter_scheme == "https" else 80)
        self.filter_path = parts.path or "/v1/filter"
        self.threshold = threshold
        self.fail_open = fail_open
        self.schemas_dir = Path(schemas_dir) if schemas_dir else DEFAULT_SCHEMAS_DIR
        # Field selectors (parsed from schemas_dir) govern which JSON values are
        # sent to the filter; an empty trie means no request field is filtered.
        self.field_selectors = _load_field_selectors(self.schemas_dir)
        self._field_trie = _build_selector_trie(self.field_selectors)
        self.cache = EntityCache()
        # Hosts that have received a redacted request. Restoration is limited
        # to these so cached PII can never be injected into an unrelated
        # service's response that merely contains placeholder-shaped text.
        self._redacted_hosts: set[str] = set()
        self._scan_sem = asyncio.Semaphore(FILTER_CONCURRENCY)

    # ---- lifecycle -------------------------------------------------------

    async def running(self) -> None:
        """Probe the filter once at startup so a dead filter is loud, not silent."""
        try:
            await asyncio.to_thread(self._call_filter, "ping")
        except Exception as exc:
            consequence = (
                "requests with JSON bodies will pass through UNREDACTED"
                if self.fail_open
                else "requests with JSON bodies will be BLOCKED"
            )
            logger.warning(
                "privacy filter NOT reachable at %s (%s); %s until it comes up",
                self.filter_url,
                exc,
                consequence,
            )
        else:
            logger.info("privacy filter ready at %s", self.filter_url)

    # ---- mitmproxy hooks -------------------------------------------------

    async def request(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        if req is None or self._exempt(req):
            return
        base_ct, charset = _split_content_type(req.headers.get("content-type"))
        if not _is_json_content_type(base_ct):
            return
        raw = self._raw_body(req)
        if not raw:
            return
        if len(raw) > MAX_REQUEST_BYTES:
            self._refuse(
                flow,
                f"{len(raw)}-byte JSON body exceeds the {MAX_REQUEST_BYTES}-byte "
                f"redaction limit",
            )
            return
        try:
            obj = json.loads(raw)
        except ValueError:
            self._refuse(
                flow,
                "body declared as JSON does not parse (mislabeled content type "
                "or undecodable content-encoding), so it cannot be redacted",
            )
            return

        # Only the JSON values named by the schema selectors are scanned; a body
        # that matches none of them is forwarded untouched (never filtered).
        strings = {
            s for s in _iter_selected(obj, self._field_trie) if self._scan_worthy(s)
        }
        if not strings:
            return
        try:
            entities_by_string, failures = await self._scan_strings(strings)

            def leaf(s: str) -> tuple[str, int]:
                entities = entities_by_string.get(s)
                return self._apply_entities(s, entities) if entities else (s, 0)

            obj, count = _map_selected(obj, self._field_trie, leaf)
        except Exception:
            # A bug in this addon, not a filter outage — say so, loudly.
            logger.exception(
                "privacy filter: internal error redacting %s %s",
                req.method,
                req.pretty_url,
            )
            self._refuse(flow, "internal privacy-filter error (see proxy log)")
            return

        if failures:
            if not self.fail_open:
                self._refuse(flow, f"privacy filter unavailable ({failures[0]})")
                return
            # Fail-open: forward with whatever redaction succeeded rather than
            # dropping already-identified entities back to cleartext.
            logger.warning(
                "privacy filter unavailable for %d of %d strings (%s); forwarding "
                "%s %s with partial redaction (--privacy-fail-open)",
                len(failures),
                len(strings),
                failures[0],
                req.method,
                req.pretty_url,
            )
        if not count:
            return
        # Stash the pre-redaction body so the logger (and dashboard) can show
        # the before/after of what actually left the machine. Only set when a
        # redaction happened, so its presence means "this body was changed".
        flow.metadata["privacy_request_original_body"] = raw.decode(
            charset or "utf-8", "replace"
        )
        req.content = _dump_json_for_charset(obj, charset)
        self._redacted_hosts.add(self._host_of(req))
        flow.metadata["privacy_redactions"] = count

    def response(self, flow: http.HTTPFlow) -> None:
        resp = flow.response
        req = flow.request
        if resp is None or req is None or not len(self.cache):
            return
        if self._exempt(req) or self._host_of(req) not in self._redacted_hosts:
            return
        base_ct, declared_charset = _split_content_type(
            resp.headers.get("content-type")
        )
        # A missing Content-Type is treated as restorable text: leaking a
        # placeholder to the client is worse than scanning a headerless body.
        if base_ct and not _is_restorable_content_type(base_ct):
            return
        raw = self._raw_body(resp)
        if not raw or len(raw) > MAX_RESPONSE_BYTES:
            return
        if b"[" not in raw:  # cheap byte-level pre-check before any decode
            return
        text, codec = self._decode_body(raw, declared_charset)
        if text is None or "[" not in text:
            return
        # The upstream body still carries placeholders; keep a copy so the
        # dashboard can show it against the restored version below.
        original_text = text

        count = 0
        if _is_json_content_type(base_ct):
            try:
                obj = json.loads(text)
            except ValueError:
                # Mislabeled NDJSON/partial JSON: still JSON string context.
                text, count = self.cache.restore_text(text, escape=_json_string_escape)
            else:
                obj, count = _map_strings(obj, self.cache.restore_text)
                if count:
                    text = json.dumps(obj, ensure_ascii=False)
        elif base_ct in ("text/event-stream", "application/x-ndjson"):
            # SSE/NDJSON stream a reply token-by-token, so one placeholder can be
            # split across frames. Reassemble the frames' string values before
            # matching so a straddling placeholder is still restored.
            text, count = self._restore_stream(text)
        elif base_ct in ("application/xml", "text/xml"):
            text, count = self.cache.restore_text(text, escape=_xml_escape)
        else:  # other text/*, or no content type at all
            text, count = self.cache.restore_text(text)
        if not count:
            return
        flow.metadata["privacy_response_original_body"] = original_text
        try:
            resp.content = text.encode(codec)
        except UnicodeEncodeError:
            # Original contains characters the body's codec can't express;
            # re-encode as UTF-8 and say so in the header.
            resp.content = text.encode("utf-8")
            self._set_charset(resp, "utf-8")
        flow.metadata["privacy_restored"] = count

    def _restore_stream(self, text: str) -> tuple[str, int]:
        """Restore placeholders in an SSE/NDJSON body, spanning frame boundaries.

        A streamed reply is chunked token by token, so a single placeholder can
        arrive split across frames. To match it we reassemble each JSON field
        *by its path* across all frames (e.g. every frame's
        ``choices[0].delta.content``) and restore that sequence as one text —
        never joining unrelated fields, which would both miss real splits (when
        ``id``/``model`` strings fall between two content deltas) and risk a
        false match spanning two independent values. Non-JSON lines (SSE
        ``event:``/``id:`` fields, ``data: [DONE]``, plain-text payloads) are
        scanned for whole placeholders in place. Only frames that actually
        changed are re-serialised, so untouched frames keep their exact bytes.
        """
        lines = text.split("\n")
        # Each frame: (line index, data: prefix, parsed obj, [(path, value)...], had CR).
        frames: list[tuple[int, str, object, list, bool]] = []
        total = 0
        for idx, line in enumerate(lines):
            parsed = _parse_stream_json_line(line.rstrip("\r"))
            if parsed is None:
                restored, n = self.cache.restore_text(line)
                if n:
                    lines[idx] = restored
                    total += n
                continue
            prefix, obj = parsed
            pairs = list(_iter_json_string_paths(obj, ()))
            frames.append((idx, prefix, obj, pairs, line.endswith("\r")))

        # Group each frame's string values by JSON path, preserving frame order.
        groups: dict[tuple, list[tuple[int, int]]] = {}
        values: list[list[str]] = []
        for fi, (_, _, _, pairs, _) in enumerate(frames):
            values.append([value for _, value in pairs])
            for pos, (path, _) in enumerate(pairs):
                groups.setdefault(path, []).append((fi, pos))

        changed: set[int] = set()
        for refs in groups.values():
            restored, count = self.cache.restore_segments(
                [values[fi][pos] for fi, pos in refs]
            )
            if not count:
                continue
            total += count
            for (fi, pos), value in zip(refs, restored):
                if value != values[fi][pos]:
                    values[fi][pos] = value
                    changed.add(fi)

        if not total:
            return text, 0
        for fi in changed:
            idx, prefix, obj, _, had_cr = frames[fi]
            rebuilt = prefix + json.dumps(
                _rebuild_json_strings(obj, iter(values[fi])), ensure_ascii=False
            )
            lines[idx] = rebuilt + "\r" if had_cr else rebuilt
        return "\n".join(lines), total

    def websocket_start(self, flow: http.HTTPFlow) -> None:
        if flow.request is not None and not self._exempt(flow.request):
            logger.warning(
                "privacy filter: WebSocket to %s is NOT filtered "
                "(unsupported transport; see README limitations)",
                flow.request.pretty_host,
            )

    # ---- redaction -------------------------------------------------------

    def _scan_worthy(self, s: str) -> bool:
        if len(s) < MIN_STRING_LEN:
            return False
        if len(s) >= BLOB_MIN_LEN and " " not in s and "\n" not in s and "\t" not in s:
            logger.debug(
                "privacy filter: skipping %d-char whitespace-free string "
                "(blob heuristic)",
                len(s),
            )
            return False
        return True

    async def _scan_strings(
        self, strings: set[str]
    ) -> tuple[dict[str, list], list[str]]:
        """Filter each unique string concurrently.

        Returns (entities per string, filter-failure messages). Filter outages
        are collected per string — not raised — so the caller can decide
        between blocking and partial redaction. Non-filter exceptions (bugs)
        propagate.
        """
        entities_by_string: dict[str, list] = {}
        failures: list[str] = []

        async def scan(s: str) -> None:
            async with self._scan_sem:
                try:
                    entities_by_string[s] = await asyncio.to_thread(
                        self._call_filter, s
                    )
                except PrivacyFilterError as exc:
                    failures.append(str(exc))

        await asyncio.gather(*(scan(s) for s in strings))
        return entities_by_string, failures

    def _apply_entities(self, s: str, entities: list[dict]) -> tuple[str, int]:
        """Replace entity byte-spans with placeholders (offsets are UTF-8 bytes)."""
        data = s.encode("utf-8")
        accepted: list[dict] = []
        last_end = 0
        # Prefer the longer span when two start together; drop later overlaps.
        for ent in sorted(
            (e for e in entities if self._valid_entity(e, data)),
            key=lambda e: (e["start"], e["start"] - e["end"]),
        ):
            if ent["start"] < last_end:
                continue
            accepted.append(ent)
            last_end = ent["end"]
        if not accepted:
            return s, 0
        for ent in reversed(accepted):
            original = data[ent["start"] : ent["end"]].decode("utf-8")
            ph = self.cache.placeholder(ent.get("label", "entity"), original)
            data = data[: ent["start"]] + ph.encode("ascii") + data[ent["end"] :]
        return data.decode("utf-8"), len(accepted)

    def _valid_entity(self, ent: object, data: bytes) -> bool:
        if not isinstance(ent, dict):
            return False
        start, end = ent.get("start"), ent.get("end")
        if isinstance(start, bool) or isinstance(end, bool):
            return False
        if not (isinstance(start, int) and isinstance(end, int)):
            return False
        if not 0 <= start < end <= len(data):
            return False
        # The API drops spans below the threshold itself; re-check defensively.
        score = ent.get("score")
        if isinstance(score, (int, float)) and score < self.threshold:
            return False
        try:
            span = data[start:end].decode("utf-8")
        except UnicodeDecodeError:
            return False
        expected = ent.get("text")
        return expected is None or expected == span

    # ---- plumbing --------------------------------------------------------

    @staticmethod
    def _host_of(request: http.Request) -> str:
        return request.pretty_host.strip(".").lower()

    def _exempt(self, request: http.Request) -> bool:
        host = self._host_of(request)
        for suffix in YOUTUBE_SUFFIXES:
            if host == suffix or host.endswith("." + suffix):
                return True
        # Never touch traffic to the privacy filter itself, so other local
        # processes calling it while intercepted don't get their text mangled.
        # Loopback aliases only count when the filter itself is loopback.
        if request.port == self.filter_port:
            if host == self.filter_host.lower():
                return True
            if self.filter_host in LOOPBACK_HOSTS and host in LOOPBACK_HOSTS:
                return True
        return False

    @staticmethod
    def _raw_body(message: http.Message) -> bytes:
        try:
            raw = message.get_content(strict=False)
        except Exception:
            raw = message.raw_content
        return raw or b""

    @staticmethod
    def _decode_body(raw: bytes, declared_charset: str | None) -> tuple[str | None, str]:
        """Decode with the declared charset first, then UTF-8, then latin-1."""
        encodings: list[str] = []
        for encoding in (declared_charset, "utf-8", "latin-1"):
            if encoding and encoding.lower() not in encodings:
                encodings.append(encoding.lower())
        for encoding in encodings:
            try:
                return raw.decode(encoding), encoding
            except (UnicodeDecodeError, LookupError):
                continue
        return None, ""

    @staticmethod
    def _set_charset(message: http.Message, charset: str) -> None:
        header = message.headers.get("content-type")
        if not header:
            return
        if re.search(r"charset\s*=", header, flags=re.I):
            message.headers["content-type"] = re.sub(
                r"charset\s*=\s*[^;\s]+", f"charset={charset}", header, flags=re.I
            )
        else:
            message.headers["content-type"] = f"{header}; charset={charset}"

    def _call_filter(self, text: str) -> list[dict]:
        """POST to the filter API. Runs in a worker thread; deliberately uses
        http.client so proxy env vars / the system proxy can never reroute it."""
        payload = json.dumps({"text": text, "threshold": self.threshold}).encode("utf-8")
        conn_cls = HTTPSConnection if self.filter_scheme == "https" else HTTPConnection
        conn = conn_cls(self.filter_host, self.filter_port, timeout=FILTER_TIMEOUT)
        try:
            conn.request(
                "POST",
                self.filter_path,
                body=payload,
                headers={"Content-Type": "application/json"},
            )
            resp = conn.getresponse()
            body = resp.read()
            if resp.status != 200:
                raise PrivacyFilterError(f"filter API returned HTTP {resp.status}")
            parsed = json.loads(body)
            entities = parsed.get("entities") if isinstance(parsed, dict) else None
            if not isinstance(entities, list):
                raise PrivacyFilterError(
                    "filter API response is not an object with an 'entities' list"
                )
            return entities
        except (OSError, HTTPException, ValueError) as exc:
            raise PrivacyFilterError(str(exc) or type(exc).__name__) from exc
        finally:
            conn.close()

    def _refuse(self, flow: http.HTTPFlow, reason: str) -> None:
        """Apply the fail policy to a request that cannot be redacted."""
        req = flow.request
        if self.fail_open:
            logger.warning(
                "privacy filter: %s; passing %s %s through UNREDACTED "
                "(--privacy-fail-open)",
                reason,
                req.method,
                req.pretty_url,
            )
            return
        logger.warning(
            "privacy filter: %s; blocking %s %s (fail-closed; use "
            "--privacy-fail-open to forward unredacted)",
            reason,
            req.method,
            req.pretty_url,
        )
        flow.metadata["privacy_blocked"] = True
        flow.response = http.Response.make(
            502,
            (
                f"llm-firewall: {reason}; request blocked so unredacted data does "
                f"not leave this machine. Privacy filter: {self.filter_url}. "
                f"Rerun the proxy with --privacy-fail-open to forward anyway.\n"
            ).encode("utf-8"),
            {"content-type": "text/plain"},
        )


# mitmproxy discovers module-level `addons`.
addons = [PrivacyFilter()]
