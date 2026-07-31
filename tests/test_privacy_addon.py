"""Unit tests for the privacy addon: redaction, caching, and restoration.

The filter API is stubbed out (``_call_filter`` replaced per-test), so these
run without the real privacy-filter service or a live proxy.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

from mitmproxy.test import tflow

from llm_firewall import privacy_addon
from llm_firewall.privacy_addon import (
    EntityCache,
    PrivacyFilter,
    PrivacyFilterError,
)

# Schema selectors covering every JSON field these tests redact through. The
# addon only scans fields named here, so the fixture declares them explicitly
# instead of relying on any particular default schema shipped with the package.
TEST_SCHEMAS_DIR = Path(tempfile.mkdtemp(prefix="llm_firewall_schemas_"))
(TEST_SCHEMAS_DIR / "fields.txt").write_text(
    "\n".join(
        [
            "content",
            "text",
            "a",
            "b",
            "messages[].content",
            "messages[].content[].text",
        ]
    ),
    encoding="utf-8",
)

PII_TEXT = "Contact John Doe at jdoe@example.com"


def entities_for(text: str, *spans: tuple[str, str]) -> list[dict]:
    """Build filter-API entities with byte offsets, like the real service."""
    data = text.encode("utf-8")
    out = []
    for substring, label in spans:
        start = data.find(substring.encode("utf-8"))
        assert start != -1, f"{substring!r} not in {text!r}"
        out.append(
            {
                "start": start,
                "end": start + len(substring.encode("utf-8")),
                "label": label,
                "score": 0.99,
                "text": substring,
            }
        )
    return out


PII_ENTITIES = entities_for(
    PII_TEXT, ("John", "first_name"), ("Doe", "last_name"), ("jdoe@example.com", "email")
)


def make_addon(entity_map: dict[str, list[dict]] | None = None, fail: bool = False, **kw):
    kw.setdefault("schemas_dir", TEST_SCHEMAS_DIR)
    addon = PrivacyFilter(**kw)
    if fail:

        def boom(text: str) -> list[dict]:
            raise PrivacyFilterError("connection refused")

        addon._call_filter = boom
    else:
        table = entity_map or {}
        addon._call_filter = lambda text: table.get(text, [])
    return addon


def make_flow(body, host="api.example.com", content_type="application/json", resp=False):
    f = tflow.tflow(resp=resp)
    f.request.scheme = "https"
    f.request.host = host
    f.request.port = 443
    f.request.headers["host"] = host
    if isinstance(body, (dict, list)):
        body = json.dumps(body, ensure_ascii=False)
    f.request.headers["content-type"] = content_type
    f.request.content = body.encode("utf-8") if isinstance(body, str) else body
    return f


def run(coro):
    return asyncio.run(coro)


# ---- request-side redaction ---------------------------------------------


def test_redacts_json_body_with_placeholders():
    addon = make_addon({PII_TEXT: PII_ENTITIES})
    flow = make_flow({"messages": [{"role": "user", "content": PII_TEXT}]})
    run(addon.request(flow))

    body = json.loads(flow.request.content)
    assert body["messages"][0]["content"] == "Contact [FIRST_NAME_1] [LAST_NAME_1] at [EMAIL_1]"
    assert body["messages"][0]["role"] == "user"  # keys and clean values untouched
    assert flow.metadata["privacy_redactions"] == 3
    assert "api.example.com" in addon._redacted_hosts
    assert flow.response is None
    if "content-length" in flow.request.headers:
        assert int(flow.request.headers["content-length"]) == len(flow.request.raw_content)


def test_stashes_original_body_for_dashboard():
    addon = make_addon({PII_TEXT: PII_ENTITIES})
    original = {"messages": [{"role": "user", "content": PII_TEXT}]}
    flow = make_flow(original)
    run(addon.request(flow))

    # The pre-redaction body is preserved so the dashboard can render the
    # before/after; it must still hold the raw PII the wire body no longer does.
    stashed = json.loads(flow.metadata["privacy_request_original_body"])
    assert stashed == original
    assert PII_TEXT not in flow.request.content.decode("utf-8")


def test_logger_caps_oversized_bodies():
    from llm_firewall import logger_addon

    text, is_b64, trunc = logger_addon._cap_body("x" * (logger_addon.MAX_LOGGED_BODY + 1), False)
    assert trunc is True
    assert len(text) < logger_addon.MAX_LOGGED_BODY + 200
    assert "truncated" in text
    # Big binary bodies become a short marker, not megabytes of base64.
    marker, is_b64, trunc = logger_addon._cap_body("A" * (logger_addon.MAX_LOGGED_BODY + 1), True)
    assert trunc is True and is_b64 is False
    assert "binary" in marker
    # Small bodies pass through untouched.
    same, is_b64, trunc = logger_addon._cap_body("hello", False)
    assert same == "hello" and trunc is False


def test_no_original_body_stashed_when_nothing_redacted():
    addon = make_addon({})  # filter finds no entities
    flow = make_flow({"messages": [{"role": "user", "content": "hello there"}]})
    run(addon.request(flow))

    # Absence of the key is how the dashboard knows the body was unchanged.
    assert "privacy_request_original_body" not in flow.metadata


def test_nested_selector_redacts_only_named_field():
    # `messages[].content[].text` reaches into the list-of-parts content shape;
    # sibling fields (`image`) and unlisted keys (`role`, top-level `note`) are
    # left untouched even though they hold scan-worthy strings.
    addon = make_addon({"call John": entities_for("call John", ("John", "first_name"))})
    flow = make_flow(
        {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "call John"},
                        {"type": "image", "image": "leak me?"},
                    ],
                }
            ],
            "note": "leak me too?",
        }
    )
    run(addon.request(flow))

    body = json.loads(flow.request.content)
    assert body["messages"][0]["content"][0]["text"] == "call [FIRST_NAME_1]"
    assert body["messages"][0]["content"][1]["image"] == "leak me?"
    assert body["messages"][0]["role"] == "user"
    assert body["note"] == "leak me too?"
    assert flow.metadata["privacy_redactions"] == 1


def test_body_with_no_selected_fields_is_not_filtered():
    # A body that matches none of the schema selectors is forwarded untouched,
    # and the filter is never consulted (fail=True would raise if it were).
    addon = make_addon(fail=True)
    flow = make_flow({"subject": PII_TEXT, "notes": [PII_TEXT]})
    original = flow.request.content
    run(addon.request(flow))

    assert flow.request.content == original
    assert flow.response is None
    assert "privacy_redactions" not in flow.metadata


def test_empty_schemas_dir_filters_nothing(tmp_path):
    addon = make_addon(fail=True, schemas_dir=tmp_path)
    flow = make_flow({"content": PII_TEXT, "messages": [{"content": PII_TEXT}]})
    original = flow.request.content
    run(addon.request(flow))

    assert flow.request.content == original
    assert flow.response is None


def test_multibyte_byte_offsets():
    text = "Émile écrit à jdoe@example.com"
    addon = make_addon({text: entities_for(text, ("jdoe@example.com", "email"))})
    flow = make_flow({"content": text})
    run(addon.request(flow))

    assert json.loads(flow.request.content)["content"] == "Émile écrit à [EMAIL_1]"


def test_same_entity_same_placeholder_across_flows():
    addon = make_addon(
        {
            "mail jdoe@example.com": entities_for(
                "mail jdoe@example.com", ("jdoe@example.com", "email")
            ),
            "cc jdoe@example.com and other@example.com": entities_for(
                "cc jdoe@example.com and other@example.com",
                ("jdoe@example.com", "email"),
                ("other@example.com", "email"),
            ),
        }
    )
    first = make_flow({"content": "mail jdoe@example.com"})
    second = make_flow({"content": "cc jdoe@example.com and other@example.com"})
    run(addon.request(first))
    run(addon.request(second))

    assert json.loads(first.request.content)["content"] == "mail [EMAIL_1]"
    assert (
        json.loads(second.request.content)["content"] == "cc [EMAIL_1] and [EMAIL_2]"
    )


def test_youtube_host_exempt():
    addon = make_addon(fail=True)  # would raise if the filter were consulted
    flow = make_flow({"content": PII_TEXT}, host="www.youtube.com")
    original = flow.request.content
    run(addon.request(flow))

    assert flow.request.content == original
    assert flow.response is None


def test_filter_endpoint_exempt():
    addon = make_addon(fail=True)
    flow = make_flow({"text": PII_TEXT}, host="127.0.0.1")
    flow.request.scheme = "http"
    flow.request.port = 8080  # the filter API's own port
    original = flow.request.content
    run(addon.request(flow))

    assert flow.request.content == original
    assert flow.response is None


def test_remote_filter_does_not_exempt_local_loopback():
    # With a REMOTE filter host, unrelated loopback services sharing the port
    # number must still be redacted.
    addon = make_addon(
        {PII_TEXT: PII_ENTITIES},
        filter_url="http://filter.internal:8080/v1/filter",
    )
    flow = make_flow({"content": PII_TEXT}, host="127.0.0.1")
    flow.request.scheme = "http"
    flow.request.port = 8080
    run(addon.request(flow))

    assert b"[EMAIL_1]" in flow.request.content


def test_non_json_content_type_skipped():
    addon = make_addon(fail=True)
    flow = make_flow("Contact John Doe", content_type="text/plain")
    original = flow.request.content
    run(addon.request(flow))

    assert flow.request.content == original
    assert flow.response is None


def test_blob_strings_not_sent_to_filter():
    addon = make_addon(fail=True)  # any filter call would raise
    flow = make_flow({"image": "A" * 5000})
    original = flow.request.content
    run(addon.request(flow))

    assert flow.request.content == original
    assert flow.response is None


def test_fail_closed_blocks_request():
    addon = make_addon(fail=True)
    flow = make_flow({"content": PII_TEXT})
    run(addon.request(flow))

    assert flow.response is not None
    assert flow.response.status_code == 502
    assert b"privacy filter unavailable" in flow.response.content
    assert flow.metadata["privacy_blocked"] is True


def test_fail_open_passes_request_unredacted():
    addon = make_addon(fail=True, fail_open=True)
    flow = make_flow({"content": PII_TEXT})
    original = flow.request.content
    run(addon.request(flow))

    assert flow.request.content == original
    assert flow.response is None


def test_unparseable_json_follows_fail_policy():
    # Fail-closed: a body declared JSON that doesn't parse must not go upstream.
    addon = make_addon(fail=True)
    flow = make_flow("{not json", content_type="application/json")
    run(addon.request(flow))
    assert flow.response is not None
    assert flow.response.status_code == 502
    assert b"cannot be redacted" in flow.response.content

    # Fail-open: forwarded untouched.
    addon2 = make_addon(fail=True, fail_open=True)
    flow2 = make_flow("{not json", content_type="application/json")
    original = flow2.request.content
    run(addon2.request(flow2))
    assert flow2.request.content == original
    assert flow2.response is None


def test_oversized_body_follows_fail_policy(monkeypatch):
    monkeypatch.setattr(privacy_addon, "MAX_REQUEST_BYTES", 50)

    addon = make_addon(fail=True)
    flow = make_flow({"content": "x" * 100})
    run(addon.request(flow))
    assert flow.response is not None
    assert flow.response.status_code == 502
    assert b"redaction limit" in flow.response.content

    addon2 = make_addon(fail=True, fail_open=True)
    flow2 = make_flow({"content": "x" * 100})
    original = flow2.request.content
    run(addon2.request(flow2))
    assert flow2.request.content == original
    assert flow2.response is None


def test_partial_redaction_on_fail_open():
    ok_text = "mail jdoe@example.com"
    bad_text = "call 555-1234"
    table = {ok_text: entities_for(ok_text, ("jdoe@example.com", "email"))}

    def stub(text: str) -> list[dict]:
        if text == bad_text:
            raise PrivacyFilterError("timeout")
        return table.get(text, [])

    addon = PrivacyFilter(fail_open=True, schemas_dir=TEST_SCHEMAS_DIR)
    addon._call_filter = stub
    flow = make_flow({"a": ok_text, "b": bad_text})
    run(addon.request(flow))

    body = json.loads(flow.request.content)
    assert body["a"] == "mail [EMAIL_1]"  # succeeded redaction kept
    assert body["b"] == bad_text
    assert flow.response is None
    assert flow.metadata["privacy_redactions"] == 1

    # Fail-closed with the same mid-body failure: blocked, body untouched.
    addon2 = PrivacyFilter(schemas_dir=TEST_SCHEMAS_DIR)
    addon2._call_filter = stub
    flow2 = make_flow({"a": ok_text, "b": bad_text})
    original = flow2.request.content
    run(addon2.request(flow2))
    assert flow2.response is not None and flow2.response.status_code == 502
    assert flow2.request.content == original


def test_overlapping_and_invalid_entities():
    text = "John Doe"
    addon = make_addon()
    whole = {"start": 0, "end": 8, "label": "name", "score": 0.9, "text": "John Doe"}
    inner = {"start": 0, "end": 4, "label": "first_name", "score": 0.95, "text": "John"}
    wrong_text = {"start": 5, "end": 8, "label": "last_name", "score": 0.9, "text": "Poe"}
    out_of_range = {"start": 4, "end": 99, "label": "x", "score": 0.9, "text": "Doe"}
    redacted, count = addon._apply_entities(text, [inner, whole, wrong_text, out_of_range])

    assert redacted == "[NAME_1]"
    assert count == 1


def test_bool_offsets_rejected():
    addon = make_addon()
    ent = {"start": False, "end": True, "label": "x", "score": 0.9, "text": "J"}
    assert addon._apply_entities("John", [ent]) == ("John", 0)


def test_low_score_entity_rejected():
    addon = make_addon()  # threshold 0.5
    ent = entities_for("John", ("John", "first_name"))[0]
    ent["score"] = 0.2
    assert addon._apply_entities("John", [ent]) == ("John", 0)


def test_https_filter_url_scheme_and_port():
    addon = PrivacyFilter(filter_url="https://filter.example/v1/filter")
    assert addon.filter_scheme == "https"
    assert addon.filter_port == 443


# ---- response-side restoration ------------------------------------------


def prime(addon: PrivacyFilter, host: str = "api.example.com") -> dict[str, str]:
    addon._redacted_hosts.add(host)
    return {
        "first": addon.cache.placeholder("first_name", "John"),
        "email": addon.cache.placeholder("email", "jdoe@example.com"),
    }


def test_response_restore_json():
    addon = make_addon()
    ph = prime(addon)
    flow = make_flow({}, resp=True)
    flow.response.headers["content-type"] = "application/json"
    flow.response.content = json.dumps(
        {"reply": f"Thanks {ph['first']}, mail sent to {ph['email']}"}
    ).encode()
    addon.response(flow)

    assert json.loads(flow.response.content)["reply"] == (
        "Thanks John, mail sent to jdoe@example.com"
    )
    assert flow.metadata["privacy_restored"] == 2


def test_response_restore_sse_with_json_escaping():
    addon = make_addon()
    prime(addon)
    ph = addon.cache.placeholder("note", 'say "hi"')
    flow = make_flow({}, resp=True)
    flow.response.headers["content-type"] = "text/event-stream"
    flow.response.content = f'data: {{"delta":"{ph} done"}}\n\n'.encode()
    addon.response(flow)

    line = flow.response.content.decode().splitlines()[0]
    assert json.loads(line.removeprefix("data: "))["delta"] == 'say "hi" done'


def _sse_contents(body: bytes) -> str:
    """Concatenate the OpenAI-style delta.content across an SSE body."""
    out = []
    for line in body.decode().splitlines():
        payload = line.removeprefix("data: ").strip()
        if not payload or payload == "[DONE]":
            continue
        out.append(json.loads(payload)["choices"][0]["delta"]["content"])
    return "".join(out)


def test_response_restore_sse_placeholder_split_across_frames():
    # A placeholder streamed token-by-token: "[" arrives in one frame and the
    # rest in the next, so it is never contiguous in the raw body.
    addon = make_addon()
    addon._redacted_hosts.add("api.example.com")
    occ = addon.cache.placeholder("occupation", "Doctor")  # [OCCUPATION_1]
    last = addon.cache.placeholder("last_name", "Smith")  # [LAST_NAME_1]
    flow = make_flow({}, resp=True)
    flow.response.headers["content-type"] = "text/event-stream"
    frame = lambda c: 'data: %s\n\n' % json.dumps(
        {"choices": [{"delta": {"content": c}}]}
    )
    flow.response.content = (
        frame("You are a [")
        + frame(occ[1:] + " and a " + last)  # "OCCUPATION_1] and a [LAST_NAME_1]"
        + "data: [DONE]\n\n"
    ).encode()
    addon.response(flow)

    # The user-visible reassembled stream has both originals, no placeholders.
    assert _sse_contents(flow.response.content) == "You are a Doctor and a Smith"
    assert flow.metadata["privacy_restored"] == 2


def test_response_restore_ndjson_split_across_lines():
    addon = make_addon()
    addon._redacted_hosts.add("api.example.com")
    email = addon.cache.placeholder("email", "jdoe@example.com")  # [EMAIL_1]
    flow = make_flow({}, resp=True)
    flow.response.headers["content-type"] = "application/x-ndjson"
    head, tail = email[:4], email[4:]  # "[EMA", "IL_1]"
    flow.response.content = (
        json.dumps({"t": "mail " + head}) + "\n" + json.dumps({"t": tail}) + "\n"
    ).encode()
    addon.response(flow)

    joined = "".join(
        json.loads(line)["t"] for line in flow.response.content.decode().splitlines()
    )
    assert joined == "mail jdoe@example.com"
    assert flow.metadata["privacy_restored"] == 1


def _openai_frame(content: str) -> str:
    """A realistic OpenAI chunk carrying id/object/model beside the content delta."""
    return "data: %s\n\n" % json.dumps(
        {
            "id": "chatcmpl-abc",
            "object": "chat.completion.chunk",
            "model": "gpt-4o",
            "choices": [{"index": 0, "delta": {"content": content}}],
        }
    )


def test_response_restore_sse_split_with_interleaved_metadata():
    # Real provider frames repeat id/object/model every chunk, so consecutive
    # content deltas are NOT adjacent in the body. Restoration must reassemble by
    # field path, not by naively concatenating every string value in the frames.
    addon = make_addon()
    addon._redacted_hosts.add("api.example.com")
    occ = addon.cache.placeholder("occupation", "Doctor")  # [OCCUPATION_1]
    flow = make_flow({}, resp=True)
    flow.response.headers["content-type"] = "text/event-stream"
    flow.response.content = (
        _openai_frame("You are a [") + _openai_frame(occ[1:]) + "data: [DONE]\n\n"
    ).encode()
    addon.response(flow)

    assert _sse_contents(flow.response.content) == "You are a Doctor"
    assert flow.metadata["privacy_restored"] == 1


def test_response_restore_does_not_join_unrelated_fields():
    # Two independent fields that happen to abut as "[EMAIL" + "_1]" must NOT be
    # spliced into a placeholder — that would inject PII into one and truncate
    # the other. Fields at different paths are reassembled separately.
    addon = make_addon()
    addon._redacted_hosts.add("api.example.com")
    addon.cache.placeholder("email", "jdoe@example.com")  # [EMAIL_1]
    flow = make_flow({}, resp=True)
    flow.response.headers["content-type"] = "text/event-stream"
    flow.response.content = (
        "data: %s\n\n"
        % json.dumps({"id": "z[EMAIL", "choices": [{"delta": {"content": "_1] hi"}}]})
    ).encode()
    addon.response(flow)

    frame = json.loads(flow.response.content.decode().splitlines()[0].removeprefix("data: "))
    assert frame["id"] == "z[EMAIL"  # untouched
    assert frame["choices"][0]["delta"]["content"] == "_1] hi"  # untouched
    assert "privacy_restored" not in flow.metadata


def test_response_restore_sse_non_json_line():
    # A plain-text SSE line among JSON frames still gets whole placeholders
    # restored (it is not skipped just because other lines are JSON).
    addon = make_addon()
    addon._redacted_hosts.add("api.example.com")
    name = addon.cache.placeholder("name", "Jane")  # [NAME_1]
    flow = make_flow({}, resp=True)
    flow.response.headers["content-type"] = "text/event-stream"
    flow.response.content = (
        'data: {"v": 1}\n\ndata: hello %s\n\n' % name
    ).encode()
    addon.response(flow)

    assert b"hello Jane" in flow.response.content
    assert flow.metadata["privacy_restored"] == 1


def test_response_restore_sse_preserves_crlf():
    addon = make_addon()
    addon._redacted_hosts.add("api.example.com")
    email = addon.cache.placeholder("email", "x@y.com")  # [EMAIL_1]
    flow = make_flow({}, resp=True)
    flow.response.headers["content-type"] = "text/event-stream"
    flow.response.content = ('data: %s\r\n\r\n' % json.dumps({"v": email})).encode()
    addon.response(flow)

    text = flow.response.content.decode()
    assert "x@y.com" in text
    assert text.startswith("data: ") and "\r\n" in text  # CRLF framing kept


def test_response_restore_large_body_without_placeholder_is_fast():
    # A multi-MB streamed body with a bare "[" but no known placeholder must
    # early-out instead of doing quadratic work on the event loop.
    import time

    addon = make_addon()
    addon._redacted_hosts.add("api.example.com")
    addon.cache.placeholder("email", "x@y.com")  # cache non-empty
    flow = make_flow({}, resp=True)
    flow.response.headers["content-type"] = "application/x-ndjson"
    big = "x" * (4 * 1024 * 1024) + "["
    flow.response.content = (json.dumps({"t": big}) + "\n").encode()
    start = time.monotonic()
    addon.response(flow)
    assert time.monotonic() - start < 2.0
    assert "privacy_restored" not in flow.metadata


def test_response_restore_xml_escaped():
    addon = make_addon()
    prime(addon)
    ph = addon.cache.placeholder("note", 'Q&A <b> "x"')
    flow = make_flow({}, resp=True)
    flow.response.headers["content-type"] = "application/xml"
    flow.response.content = f"<r>{ph}</r>".encode()
    addon.response(flow)

    assert flow.response.content == b"<r>Q&amp;A &lt;b&gt; &quot;x&quot;</r>"


def test_response_json_parse_fallback_escaped():
    # NDJSON mislabeled as application/json: restore must stay JSON-escaped.
    addon = make_addon()
    prime(addon)
    ph = addon.cache.placeholder("note", 'say "hi"')
    flow = make_flow({}, resp=True)
    flow.response.headers["content-type"] = "application/json"
    flow.response.content = f'{{"d":"{ph}"}}\n{{"d":"{ph}"}}'.encode()
    addon.response(flow)

    line = flow.response.content.decode().splitlines()[0]
    assert json.loads(line)["d"] == 'say "hi"'


def test_response_missing_content_type_restored():
    addon = make_addon()
    ph = prime(addon)
    flow = make_flow({}, resp=True)
    if "content-type" in flow.response.headers:
        del flow.response.headers["content-type"]
    flow.response.content = f"see {ph['email']}".encode()
    addon.response(flow)

    assert flow.response.content == b"see jdoe@example.com"


def test_response_declared_charset_utf16_restored():
    addon = make_addon()
    ph = prime(addon)
    flow = make_flow({}, resp=True)
    flow.response.headers["content-type"] = "application/json; charset=utf-16"
    flow.response.content = json.dumps({"reply": f"mail {ph['email']}"}).encode("utf-16")
    addon.response(flow)

    decoded = json.loads(flow.response.content.decode("utf-16"))
    assert decoded["reply"] == "mail jdoe@example.com"


def test_response_restore_gated_by_redacted_host():
    addon = make_addon()
    ph = prime(addon)  # registers api.example.com only
    flow = make_flow({}, host="other.example.com", resp=True)
    flow.response.headers["content-type"] = "application/json"
    body = json.dumps({"r": ph["email"]}).encode()
    flow.response.content = body
    addon.response(flow)

    assert flow.response.content == body  # unrelated host: untouched
    assert "privacy_restored" not in flow.metadata


def test_response_unknown_placeholder_untouched():
    addon = make_addon()
    prime(addon)
    flow = make_flow({}, resp=True)
    flow.response.headers["content-type"] = "application/json"
    body = json.dumps({"reply": "see [SOMETHING_9]"}).encode()
    flow.response.content = body
    addon.response(flow)

    assert flow.response.content == body
    assert "privacy_restored" not in flow.metadata


def test_response_youtube_exempt():
    addon = make_addon()
    ph = prime(addon)
    addon._redacted_hosts.add("www.youtube.com")  # ensure exemption is the gate
    flow = make_flow({}, host="www.youtube.com", resp=True)
    flow.response.headers["content-type"] = "application/json"
    body = json.dumps({"reply": ph["first"]}).encode()
    flow.response.content = body
    addon.response(flow)

    assert flow.response.content == body


# ---- cache ---------------------------------------------------------------


def test_cache_label_slugging_and_counters():
    cache = EntityCache()
    assert cache.placeholder("first_name", "John") == "[FIRST_NAME_1]"
    assert cache.placeholder("e-mail!", "a@b.c") == "[E_MAIL_1]"
    assert cache.placeholder("first_name", "Jane") == "[FIRST_NAME_2]"
    assert cache.placeholder("first_name", "John") == "[FIRST_NAME_1]"  # stable
    assert len(cache) == 3


def test_cache_restore_text_counts():
    cache = EntityCache()
    ph = cache.placeholder("email", "jdoe@example.com")
    text, count = cache.restore_text(f"mail {ph} twice {ph}, skip [EMAIL_99]")
    assert text == "mail jdoe@example.com twice jdoe@example.com, skip [EMAIL_99]"
    assert count == 2
