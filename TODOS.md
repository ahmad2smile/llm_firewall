# TODOs

Potential future work flagged during the max-effort code review of the
schema-selector + SSE/NDJSON stream-restoration changes. These were **not**
fixed at the time because they are pre-existing designs, configuration choices,
or out of the reviewed diff's scope.

## Privacy filter — request redaction gaps

- [ ] **Plain-string `content` leaks unredacted.** The only shipped selector is
  `messages[].content[].text` (`llm_firewall/schemas/llm_chat.txt`). The common
  OpenAI/Anthropic shape has `content` as a plain string
  (`{"messages":[{"content":"my email is ..."}]}`), which matches no selector →
  the request is forwarded **unredacted**, and because nothing matched,
  fail-closed never triggers even when the filter API is down. Consider adding a
  `messages[].content` selector (and any other common fields: `system`,
  `input`, `prompt`, `tools[].description`).

- [ ] **Empty/missing `schemas/` dir silently disables all request redaction**
  (only a warning is logged). A packaging slip or empty dir means every JSON
  request on every host is forwarded unfiltered for the life of the proxy.
  Consider failing loudly (or fail-closed) when no selectors load.

- [ ] **Import-time side effects.** `addons = [PrivacyFilter()]` constructs the
  filter at module import, which reads/sorts the schemas dir and logs warnings
  before logging/mitmproxy options are configured; a schemas dir created after
  import is never picked up by that module-level instance.

- [ ] **Top-level JSON array request bodies are never scanned.** `_iter_selected`
  / `_map_selected` bail unless the body root is a dict, so batch-style array
  bodies bypass redaction even when a selector would match each element.

- [ ] **Request re-serialization breaks body-integrity signatures.** When any
  redaction fires, the whole request body is re-serialized, invalidating a
  client-supplied `Content-MD5` / `x-amz-content-sha256` / HMAC over the exact
  bytes. (Pre-existing; only the count==0 path passes bytes through untouched.)

## Privacy filter — response restoration gaps

- [ ] **Streamed / oversized responses skip restoration silently.** The
  `response()` hook never checks `flow.response.stream` and returns early for
  bodies over `MAX_RESPONSE_BYTES` (20MB), so placeholders can reach the client
  with no warning. Consider logging when restoration is skipped.

- [ ] **Single SSE event split across multiple `data:` lines is not
  reassembled.** Per the SSE spec, consecutive `data:` lines of one event are
  joined with `\n` by the client; the per-line frame parser can't restore a
  placeholder split that way. Rare for LLM APIs, but a genuine limitation —
  worth a README "Known gaps" note. (Non-frame lines now at least get
  whole-placeholder restoration in place.)

## Dashboard

- [ ] **List polling cost.** `loadFlows()` re-fetches all summaries and rebuilds
  the entire list DOM every 4s (and on each keystroke) against an `/api/flows`
  endpoint that returns every flow ever captured with no limit. Consider a
  `?since=<id>` incremental API (the capture is append-only) plus append-only
  row rendering and a row cap.

- [ ] **`SummaryCache` lock contention.** `record()` holds the same lock as
  `summaries()` across `_refresh()` (parsing all newly appended bytes), so a
  detail click can wait behind a poll's refresh. Consider releasing the lock
  before the file seek/readline (offsets are immutable once recorded).

## Code quality (cleanup only — no behavior change)

- [ ] **Three JSON tree-walkers with identical traversal order** in
  `privacy_addon.py` (`_map_strings`, `_iter_json_string_paths`,
  `_rebuild_json_strings`) can drift; consider expressing them through one
  traversal.

- [ ] **Trie edges are anonymous 3-key dicts** (`is_list`/`terminal`/`children`)
  accessed by string literals at several call sites; a small dataclass would
  give attribute access and typo detection.

- [ ] **Test hygiene:** `TEST_SCHEMAS_DIR` is created via `tempfile.mkdtemp()` at
  test-module import time with no cleanup; prefer a pytest fixture / `tmp_path`.
