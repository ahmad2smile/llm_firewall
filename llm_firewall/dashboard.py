"""A small local web dashboard for reviewing captured flows.

The logging addon appends one JSON record per flow to ``capture.jsonl`` (see
``logger_addon.py``). Scrolling that in a terminal is painful once a session has
run for a while, so this module serves a browsable UI over the same file:

* a searchable list of every flow (filter by origin/host or URL), and
* a detail view showing request/response headers and bodies, including the
  **before/after** of the privacy redaction — the client's original request body
  next to what actually went upstream, and the upstream response next to what the
  local app saw after placeholders were restored.

It is read-only and dependency-free (stdlib ``http.server``), reading the capture
file fresh on each request so it reflects a live, still-running proxy. Bind it to
loopback only — captured traffic can contain secrets.

Usage:
    python -m llm_firewall.dashboard                 # http://127.0.0.1:8090
    python -m llm_firewall.dashboard --port 9000
    python -m llm_firewall.dashboard --no-browser

Environment:
    XAI_CAPTURE_DIR   Directory holding capture.jsonl (default ~/llm-firewall-capture)
"""

from __future__ import annotations

import argparse
import json
import logging
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from llm_firewall.logger_addon import capture_dir

logger = logging.getLogger("llm_firewall")

DEFAULT_PORT = 8090


def _capture_file() -> Path:
    return capture_dir() / "capture.jsonl"


def _iter_records(path: Path):
    """Yield ``(index, record)`` for each parseable line of the capture file.

    ``index`` is the 0-based line number and serves as a stable flow id for the
    detail endpoint. Malformed lines are skipped but still consume an index, so
    ids stay aligned with the file even if a line is later found unparseable.
    """
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as fh:
        for index, line in enumerate(fh):
            line = line.strip()
            if not line:
                continue
            try:
                yield index, json.loads(line)
            except ValueError:
                continue


def _summary(index: int, record: dict) -> dict:
    """Compact per-flow row for the list view."""
    req = record.get("request") or {}
    resp = record.get("response") or {}
    return {
        "id": index,
        "timestamp": record.get("timestamp"),
        "method": req.get("method"),
        "host": req.get("host"),
        "url": req.get("url"),
        "status": resp.get("status_code"),
        "error": record.get("error"),
        "redactions": record.get("privacy_redactions"),
        "restored": record.get("privacy_restored"),
        "blocked": bool(record.get("privacy_blocked")),
        # Flags so the list can badge flows whose body was actually rewritten.
        "request_changed": "body_original" in req,
        "response_changed": "body_original" in resp,
    }


# A line longer than this is skipped: it predates body-capping in the logger (a
# legacy multi-megabyte video chunk) and would stall or exhaust memory in the
# JSON parser. Capped captures never produce lines anywhere near this size.
MAX_LINE_PARSE = 4 * 1024 * 1024
_READ_CHUNK = 1 << 20  # 1 MiB read granularity — bounds memory on huge captures


class SummaryCache:
    """Incrementally parses capture.jsonl into per-flow summaries.

    The capture is append-only and can be huge, so re-reading and re-parsing all
    of it on every request is wasteful (and, for a live proxy, happens on every
    keystroke in the search box). This keeps the parsed summaries plus each
    record's byte offset, and on refresh reads only the bytes appended since last
    time. Shared across the server's request threads, so a lock guards the state.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._reset()

    def _reset(self) -> None:
        self._pos = 0  # bytes of complete lines already consumed
        self._next_index = 0  # line number of the next line to read
        self._summaries: list[dict] = []
        self._offsets: dict[int, int] = {}  # line index -> byte offset of its start

    def _refresh(self) -> None:
        try:
            size = self.path.stat().st_size
        except FileNotFoundError:
            self._reset()
            return
        if size < self._pos:  # truncated / rotated — rebuild from scratch
            self._reset()
        if size == self._pos:
            return
        # Read in fixed-size chunks (never the whole file) and assemble lines as
        # newlines arrive, so a 20 GB capture with multi-MB lines can't blow up
        # memory. A line that grows past MAX_LINE_PARSE stops being buffered — we
        # just wait for its newline and skip it. Only complete lines advance
        # ``self._pos``; a trailing partial line is re-read on the next refresh.
        line_start = self._pos  # abs byte offset of the current line's first byte
        frags: list[bytes] = []  # fragments of the current line (dropped if oversize)
        line_len = 0
        oversize = False
        abs_pos = self._pos
        with self.path.open("rb") as fh:
            fh.seek(self._pos)
            while abs_pos < size:
                chunk = fh.read(min(_READ_CHUNK, size - abs_pos))
                if not chunk:
                    break
                chunk_base = abs_pos
                abs_pos += len(chunk)
                start = 0
                while True:
                    nl = chunk.find(b"\n", start)
                    if nl == -1:
                        seg = chunk[start:]
                        line_len += len(seg)
                        if not oversize and line_len > MAX_LINE_PARSE:
                            oversize, frags = True, []
                        elif not oversize:
                            frags.append(seg)
                        break
                    seg = chunk[start:nl]
                    line_len += len(seg)
                    if not oversize and line_len <= MAX_LINE_PARSE:
                        frags.append(seg)
                        self._ingest(self._next_index, line_start, b"".join(frags))
                    # A complete physical line consumes an index no matter what.
                    self._next_index += 1
                    line_start = self._pos = chunk_base + nl + 1
                    frags, line_len, oversize = [], 0, False
                    start = nl + 1

    def _ingest(self, index: int, line_start: int, raw: bytes) -> None:
        line = raw.strip()
        if not line:
            return
        try:
            record = json.loads(line)
        except ValueError:
            return
        self._offsets[index] = line_start
        self._summaries.append(_summary(index, record))

    def summaries(self) -> list[dict]:
        with self._lock:
            self._refresh()
            return list(self._summaries)

    def record(self, wanted: int) -> dict | None:
        """Full record for one flow, seeked directly by its stored offset."""
        with self._lock:
            self._refresh()
            offset = self._offsets.get(wanted)
            if offset is None:
                return None
            with self.path.open("rb") as fh:
                fh.seek(offset)
                line = fh.readline()
        try:
            record = json.loads(line)
        except ValueError:
            return None
        record["id"] = wanted
        return record


class DashboardHandler(BaseHTTPRequestHandler):
    # Set by the server factory below.
    capture_path: Path = Path()
    cache: SummaryCache = None  # type: ignore[assignment]

    # Quieter logs: one line per request at debug level, not stderr spam.
    def log_message(self, fmt: str, *args) -> None:
        logger.debug("dashboard %s", fmt % args)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        route = parsed.path
        if route == "/" or route == "/index.html":
            self._send(200, "text/html; charset=utf-8", _INDEX_HTML.encode("utf-8"))
        elif route == "/api/flows":
            self._flows(parse_qs(parsed.query))
        elif route.startswith("/api/flows/"):
            self._flow_detail(route.rsplit("/", 1)[-1])
        else:
            self._send(404, "text/plain; charset=utf-8", b"not found")

    # ---- API -------------------------------------------------------------

    def _flows(self, query: dict[str, list[str]]) -> None:
        q = (query.get("q", [""])[0] or "").strip().lower()
        rows = [s for s in self.cache.summaries() if not q or _matches(s, q)]
        # Newest first — the terminal shows oldest-first, so this is the view
        # you actually want when catching up on a running session.
        rows.reverse()
        self._json(200, {"flows": rows, "count": len(rows)})

    def _flow_detail(self, raw_id: str) -> None:
        try:
            wanted = int(raw_id)
        except ValueError:
            self._json(404, {"error": "invalid flow id"})
            return
        record = self.cache.record(wanted)
        if record is None:
            self._json(404, {"error": "flow not found"})
            return
        self._json(200, record)

    # ---- plumbing --------------------------------------------------------

    def _json(self, status: int, payload: object) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send(status, "application/json; charset=utf-8", body)

    def _send(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass  # client closed the tab mid-response; nothing to do


def _matches(summary: dict, q: str) -> bool:
    """Case-insensitive substring match over the flow's host and URL."""
    for field in ("host", "url"):
        value = summary.get(field)
        if value and q in value.lower():
            return True
    return False


def _make_server(host: str, port: int, capture_path: Path) -> ThreadingHTTPServer:
    handler = type(
        "BoundHandler",
        (DashboardHandler,),
        {"capture_path": capture_path, "cache": SummaryCache(capture_path)},
    )
    return ThreadingHTTPServer((host, port), handler)


def serve_background(
    host: str, port: int, capture_path: Path | None = None
) -> ThreadingHTTPServer:
    """Start the dashboard in a daemon thread and return the server.

    Lets another process (the proxy) host the dashboard alongside itself without
    blocking. The caller owns the returned server and should ``shutdown()`` /
    ``server_close()`` it at teardown. Raises ``OSError`` if the port is taken.
    """
    server = _make_server(host, port, capture_path or _capture_file())
    threading.Thread(target=server.serve_forever, name="dashboard", daemon=True).start()
    return server


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address (default 127.0.0.1 — captures can hold secrets, keep "
        "this on loopback)",
    )
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT, help="Listen port (default %(default)s)"
    )
    parser.add_argument(
        "--no-browser", action="store_true", help="Don't open a browser tab on start"
    )
    args = parser.parse_args(argv)

    capture_path = _capture_file()
    try:
        server = _make_server(args.host, args.port, capture_path)
    except OSError as exc:
        logger.error(
            "Could not bind %s:%s (%s). Is a dashboard already running? Try "
            "--port <other>.",
            args.host,
            args.port,
            exc,
        )
        return 1

    url = f"http://{args.host}:{args.port}/"
    print(f">>> Dashboard live at {url} (Ctrl-C to stop)")
    print(f">>> Reading {capture_path}")
    if not capture_path.exists():
        print(">>> No capture.jsonl yet — run the proxy to record some traffic.")
    if not args.no_browser:
        # Delay so the browser hits a server that's already accepting.
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
    return 0


# The whole UI is a single self-contained page: a searchable flow list on the
# left, a detail pane on the right. No build step, no external assets.
_INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>llm-firewall · capture review</title>
<!-- Webfonts are a progressive enhancement: the stacks below fall back to local
     faces so the dashboard stays legible offline (or when the browser running it
     is itself pointed at this proxy). -->
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo+Black&family=IBM+Plex+Mono:wght@400;500;600;700&family=Archivo:wght@400;500;600;700&display=swap">
<style>
  :root {
    --bg: #e7e7e4; --panel: #efefec; --list: #ebebe8; --detail: #f1f1ee;
    --sheet: #ffffff; --hover: #f4f4f1; --ink: #111111; --label: #6e6e69;
    --hair: #dcdcd7; --line: #111111; --cyanT: #0b7f75; --orangeT: #c14a09;
    /* Fixed accents — identical in both themes, they carry the brand. */
    --cyan: #0fd0c0; --orange: #f0651f; --deep: #08312d;
    --mono: "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    --sans: "Archivo", Helvetica, Arial, sans-serif;
    --display: "Archivo Black", Helvetica, Arial, sans-serif;
  }
  :root[data-theme="dark"] {
    --bg: #141513; --panel: #1b1c19; --list: #181917; --detail: #1d1e1b;
    --sheet: #1f201d; --hover: #26271f; --ink: #ecece7; --label: #8f8f88;
    --hair: #2d2e2a; --line: #3a3b36; --cyanT: #3ad9c9; --orangeT: #ff8f4d;
  }
  * { box-sizing: border-box; }
  body { margin: 0; height: 100vh; display: flex; flex-direction: column;
    font-family: var(--mono); font-size: 13px;
    background: var(--bg); color: var(--ink); }
  header { padding: 14px 20px; border-bottom: 1px solid var(--line);
    display: flex; align-items: center; gap: 18px; background: var(--panel); }
  header h1 { font-family: var(--display); font-size: 20px; margin: 0; line-height: 1;
    /* 900 is a no-op for Archivo Black but keeps the fallback face heavy. */
    letter-spacing: -.02em; font-weight: 900; }
  header h1 .slash { color: var(--cyan); }
  header .count { color: var(--label); font-size: 11px; }
  #search { flex: 1; max-width: 420px; padding: 9px 11px; border: 1px solid var(--line);
    background: var(--sheet); color: var(--ink); font-family: var(--mono);
    font-size: 12px; outline: 0; }
  #search::placeholder { color: #8d8d88; }
  button { font-family: var(--mono); font-size: 10px; letter-spacing: .18em;
    text-transform: uppercase; cursor: pointer; }
  button.theme { margin-left: auto; border: 1px solid var(--line);
    background: transparent; color: var(--ink); padding: 8px 14px; }
  button.theme:hover { border-color: var(--cyan); color: var(--cyanT); }
  button.refresh { border: 0; background: var(--ink); color: var(--bg); padding: 9px 20px; }
  button.refresh:hover { background: var(--cyan); color: var(--deep); }
  main { flex: 1; display: flex; min-height: 0; }
  #list { width: 44%; max-width: 600px; min-width: 320px; overflow-y: auto;
    border-right: 1px solid var(--line); background: var(--list); }
  .row { padding: 12px 16px; border-bottom: 1px solid var(--hair); cursor: pointer;
    display: flex; flex-direction: column; gap: 6px; }
  .row:hover { background: var(--hover); }
  /* Active row reads as a lifted sheet with a cyan spine; the compensating left
     padding keeps its text aligned with the inactive rows above and below. */
  .row.active { background: var(--sheet); border-bottom-color: var(--line);
    border-left: 2px solid var(--cyan); padding-left: 14px; }
  .row .line1 { display: flex; align-items: baseline; gap: 10px; }
  .row .host { font-family: var(--sans); font-weight: 700; font-size: 14px;
    letter-spacing: -.01em; overflow: hidden; text-overflow: ellipsis;
    white-space: nowrap; }
  .row .url { font-size: 11px; color: var(--label); overflow: hidden;
    text-overflow: ellipsis; white-space: nowrap; }
  .method { font-size: 10px; letter-spacing: .14em; color: var(--label); }
  .status { font-size: 12px; margin-left: auto; color: var(--label); white-space: nowrap; }
  .status.err { color: var(--orangeT); }
  .tags { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .badge { font-size: 9px; letter-spacing: .14em; text-transform: uppercase; }
  .badge.red { color: var(--orangeT); }
  .badge.rest { color: var(--cyanT); }
  .badge.block { background: var(--ink); color: var(--bg); padding: 1px 6px; }
  #detail { flex: 1; overflow-y: auto; background: var(--detail);
    padding: 22px 24px 40px; display: flex; flex-direction: column; gap: 24px; }
  #detail .empty { color: var(--label); margin-top: 40px; text-align: center; }
  #detail .title { font-family: var(--sans); font-weight: 700; font-size: 19px;
    letter-spacing: -.01em; word-break: break-all; line-height: 1.25; }
  .head { display: flex; flex-direction: column; gap: 8px; }
  .meta { display: flex; flex-wrap: wrap; gap: 6px 24px; color: var(--label);
    font-size: 11px; }
  .meta .red { color: var(--orangeT); } .meta .rest { color: var(--cyanT); }
  h2 { font-size: 10px; letter-spacing: .22em; text-transform: uppercase;
    color: var(--label); margin: 0 0 8px; font-weight: 400; }
  .sheet { border: 1px solid var(--line); background: var(--sheet); min-width: 0; }
  /* Colour-coded strip: orange = what was on the wire before us, cyan = what we
     handed on. Same pairing in both body panels, so the eye learns it once. */
  .strip { padding: 6px 10px; border-bottom: 1px solid var(--line); font-size: 9px;
    letter-spacing: .18em; text-transform: uppercase; font-weight: 600; }
  .strip.before { background: var(--orange); color: #fff; }
  .strip.after { background: var(--cyan); color: var(--deep); }
  .strip.plain { background: var(--ink); color: var(--bg); }
  pre { margin: 0; padding: 12px; font-family: var(--mono); font-size: 12px;
    line-height: 1.55; white-space: pre-wrap; word-break: break-word; overflow-x: auto; }
  .cols { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
  ins, del { text-decoration: none; }
  ins { background: rgba(15,208,192,.28); }
  del { background: rgba(240,101,31,.24); }
  table.hdr { width: 100%; border-collapse: collapse; font-size: 12px;
    border-top: 1px solid var(--hair); }
  table.hdr td { padding: 5px 12px; vertical-align: top; word-break: break-all; }
  table.hdr td.k { color: var(--label); white-space: nowrap; width: 1px; font-size: 11px; }
  summary { cursor: pointer; padding: 8px 12px; font-size: 11px; color: var(--label);
    list-style: none; }
  summary::-webkit-details-marker { display: none; }
  @media (max-width: 900px) { .cols { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<header>
  <h1>LLM<span class="slash">/</span>FIREWALL</h1>
  <input id="search" type="search" placeholder="host or url…" autocomplete="off">
  <span class="count" id="count"></span>
  <button class="theme" id="theme">dark</button>
  <button class="refresh" id="refresh">refresh</button>
</header>
<main>
  <div id="list"></div>
  <div id="detail"><div class="empty">Select a flow to inspect its before/after.</div></div>
</main>
<script>
// Theme is a per-browser preference, so it lives in localStorage rather than on
// the server (which is stateless and read-only). Applied before the first fetch
// so there is no flash of the wrong palette.
const themeEl = document.getElementById("theme");
function applyTheme(dark) {
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  themeEl.textContent = dark ? "light" : "dark";
}
let darkMode = false;
try { darkMode = localStorage.getItem("llmfw-theme") === "dark"; } catch (e) {}
applyTheme(darkMode);
themeEl.onclick = () => {
  darkMode = !darkMode;
  try { localStorage.setItem("llmfw-theme", darkMode ? "dark" : "light"); } catch (e) {}
  applyTheme(darkMode);
};

const listEl = document.getElementById("list");
const detailEl = document.getElementById("detail");
const countEl = document.getElementById("count");
const searchEl = document.getElementById("search");
let activeId = null;
let debounce = null;

function esc(s) {
  return String(s ?? "").replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
}
function fmtTime(ts) {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString([], {hour: "2-digit", minute: "2-digit", second: "2-digit"});
}
function prettyJSON(text) {
  if (text == null) return text;
  try { return JSON.stringify(JSON.parse(text), null, 2); } catch { return text; }
}
// The row already shows the host on its own line, so the second line carries just
// the path — dropping the redundant scheme+host leaves room for long paths.
function pathOf(f) {
  const url = f.url || "";
  try { const u = new URL(url); return u.pathname + u.search; } catch { return url; }
}

async function loadFlows() {
  const q = encodeURIComponent(searchEl.value.trim());
  const res = await fetch("/api/flows?q=" + q);
  const data = await res.json();
  countEl.textContent = data.count + (data.count === 1 ? " flow" : " flows");
  listEl.innerHTML = "";
  for (const f of data.flows) {
    const row = document.createElement("div");
    row.className = "row" + (f.id === activeId ? " active" : "");
    const statusCls = (f.error || f.status >= 400) ? " err" : "";
    const statusTxt = f.error ? "ERR" : (f.status ?? "—");
    const badges = [];
    if (f.blocked) badges.push('<span class="badge block">blocked</span>');
    if (f.redactions) badges.push(`<span class="badge red">${f.redactions} redacted</span>`);
    if (f.restored) badges.push(`<span class="badge rest">${f.restored} restored</span>`);
    // A transport error has no status of its own, so surface its text instead of
    // a badge row — it is the one thing worth reading on a failed flow.
    if (f.error) badges.push(`<span class="badge red">${esc(f.error)}</span>`);
    row.dataset.id = f.id;
    row.innerHTML =
      `<div class="line1"><span class="method">${esc(f.method||"")}</span>` +
      `<span class="host">${esc(f.host||"—")}</span>` +
      `<span class="status${statusCls}">${esc(statusTxt)} · ${fmtTime(f.timestamp)}</span></div>` +
      `<div class="url">${esc(pathOf(f))}</div>` +
      (badges.length ? `<div class="tags">${badges.join("")}</div>` : "");
    row.onclick = () => {
      activeId = f.id;
      [...listEl.children].forEach(r =>
        r.classList.toggle("active", Number(r.dataset.id) === activeId));
      loadDetail(f.id);
    };
    listEl.appendChild(row);
  }
}

function section(label, inner) {
  return `<div><h2>${label}</h2>${inner}</div>`;
}
function headerTable(label, headers) {
  if (!headers || !headers.length)
    return section(label, `<div class="sheet"><pre>(none)</pre></div>`);
  const rows = headers.map(([k, v]) =>
    `<tr><td class="k">${esc(k)}</td><td>${esc(v)}</td></tr>`).join("");
  return section(label,
    `<details class="sheet"><summary>${headers.length} headers</summary>` +
    `<table class="hdr"><tbody>${rows}</tbody></table></details>`);
}

// The LCS table is O(n*m) in space and time. A 512KB body tokenizes to ~100k
// tokens, which would allocate tens of GB and freeze the tab, so cap the region
// we ever run it on.
const MAX_DIFF_CELLS = 2_000_000;

// LCS word diff over two token arrays -> [leftHTML, rightHTML].
function lcsDiff(ta, tb) {
  const n = ta.length, m = tb.length;
  const dp = Array.from({length: n+1}, () => new Int32Array(m+1));
  for (let i = n-1; i >= 0; i--)
    for (let j = m-1; j >= 0; j--)
      dp[i][j] = ta[i] === tb[j] ? dp[i+1][j+1]+1 : Math.max(dp[i+1][j], dp[i][j+1]);
  let i = 0, j = 0, left = "", right = "";
  while (i < n && j < m) {
    if (ta[i] === tb[j]) { left += esc(ta[i]); right += esc(tb[j]); i++; j++; }
    else if (dp[i+1][j] >= dp[i][j+1]) { left += `<del>${esc(ta[i])}</del>`; i++; }
    else { right += `<ins>${esc(tb[j])}</ins>`; j++; }
  }
  while (i < n) { left += `<del>${esc(ta[i])}</del>`; i++; }
  while (j < m) { right += `<ins>${esc(tb[j])}</ins>`; j++; }
  return [left, right];
}

// Word-level diff so redacted spans stand out without pulling in a library.
// Redaction changes are localized, so trim the common prefix/suffix and run the
// quadratic LCS only on the differing middle — keeps highlighting fast on large
// bodies where the full table would freeze the page.
function diffTokens(a, b) {
  const re = /(\s+|\[[A-Z0-9_]+\]|\w+|[^\w\s])/g;
  const ta = (a||"").match(re) || [], tb = (b||"").match(re) || [];
  const n = ta.length, m = tb.length;
  let pre = 0;
  while (pre < n && pre < m && ta[pre] === tb[pre]) pre++;
  let ea = n, eb = m;
  while (ea > pre && eb > pre && ta[ea-1] === tb[eb-1]) { ea--; eb--; }
  const head = ta.slice(0, pre).map(esc).join("");
  const tail = ta.slice(ea).map(esc).join("");
  const midA = ta.slice(pre, ea), midB = tb.slice(pre, eb);
  let midL, midR;
  if (midA.length * midB.length > MAX_DIFF_CELLS) {
    // Differing region still too large to diff cell-by-cell: show it plainly.
    midL = midA.map(t => `<del>${esc(t)}</del>`).join("");
    midR = midB.map(t => `<ins>${esc(t)}</ins>`).join("");
  } else {
    [midL, midR] = lcsDiff(midA, midB);
  }
  return [head + midL + tail, head + midR + tail];
}

// One bordered sheet with a colour-coded strip naming which side of the proxy the
// bytes below came from.
function panel(kind, strip, inner) {
  return `<div class="sheet"><div class="strip ${kind}">${strip}</div><pre>${inner}</pre></div>`;
}

function bodyBlock(label, msg, original, sent, isBase64) {
  if (isBase64)
    return section(label, panel("plain", "binary · base64", esc(sent||"")));
  if (original == null) {
    // No privacy change — a single body is all there is to show.
    const text = (sent == null || sent === "") ? "(empty)" : esc(prettyJSON(sent));
    return section(label, panel("plain", "unchanged", text));
  }
  const [beforeLbl, afterLbl] = msg;
  const [l, r] = diffTokens(prettyJSON(original), prettyJSON(sent));
  return section(label,
    `<div class="cols">${panel("before", beforeLbl, l)}${panel("after", afterLbl, r)}</div>`);
}

async function loadDetail(id) {
  const res = await fetch("/api/flows/" + id);
  const rec = await res.json();
  if (rec.error) { detailEl.innerHTML = `<div class="empty">${esc(rec.error)}</div>`; return; }
  const req = rec.request || {}, resp = rec.response || {};
  // First line reads as one sentence: method · outcome · time.
  const first = [esc(req.method||"")];
  if (resp.status_code != null) first.push(`${esc(resp.status_code)} ${esc(resp.reason||"")}`.trim());
  first.push(fmtTime(rec.timestamp));
  const meta = [`<span>${first.filter(Boolean).join(" · ")}</span>`];
  if (rec.client) meta.push(`<span>client ${esc(rec.client)}</span>`);
  if (rec.privacy_redactions) meta.push(`<span class="red">${rec.privacy_redactions} redacted</span>`);
  if (rec.privacy_restored) meta.push(`<span class="rest">${rec.privacy_restored} restored</span>`);
  if (rec.privacy_blocked) meta.push(`<span class="red">blocked · never sent</span>`);
  if (rec.error) meta.push(`<span class="red">error: ${esc(rec.error)}</span>`);

  let html = `<div class="head"><div class="title">${esc(req.url||"(no request)")}</div>` +
    `<div class="meta">${meta.join("")}</div></div>`;
  html += headerTable("request headers", req.headers);
  html += bodyBlock("request body", ["client sent", "sent upstream"],
    req.body_original, req.body, req.body_is_base64);
  html += headerTable("response headers", resp.headers);
  html += bodyBlock("response body", ["upstream returned", "app saw"],
    resp.body_original, resp.body, resp.body_is_base64);
  detailEl.innerHTML = html;
}

searchEl.addEventListener("input", () => {
  clearTimeout(debounce);
  debounce = setTimeout(loadFlows, 180);
});
document.getElementById("refresh").onclick = () => { loadFlows(); if (activeId != null) loadDetail(activeId); };
loadFlows();
// Poll so flows from a live proxy appear without a manual refresh. The cache on
// the server side makes each poll cheap (only newly appended bytes are parsed).
setInterval(loadFlows, 4000);
</script>
</body>
</html>
"""


if __name__ == "__main__":
    import sys

    sys.exit(main())
