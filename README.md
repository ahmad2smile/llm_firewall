# llm-firewall

A TLS-intercepting logging proxy built on [mitmproxy](https://mitmproxy.org/).
It runs in mitmproxy's **local (transparent) mode**, redirecting traffic at the
OS layer (WinDivert on Windows) and logging every request/response to disk.
Because interception happens at the network layer, clients are captured even when
they ignore proxy settings — including **Electron / Node / Python / Go** clients
that only honour `HTTPS_PROXY`, or nothing at all.

On top of logging, the proxy **redacts PII** from outbound JSON bodies through a
local privacy-filter API and transparently restores it in responses — see
[Privacy filter](#privacy-filter-pii-redaction).

## Install

```powershell
uv sync
```

## Run (zero setup)

Local mode needs to redirect the OS network stack, so run an **elevated** shell
(Windows: *Run as Administrator*; macOS/Linux: `sudo`):

```powershell
uv run python -m llm_firewall.run_proxy                        # intercept all local traffic
uv run python -m llm_firewall.run_proxy --intercept grok.exe   # only these processes
uv run python -m llm_firewall.run_proxy --intercept "node,python.exe"
uv run python -m llm_firewall.run_proxy --intercept "!chrome.exe"   # everything except Chrome
```

This does **everything automatically**:

1. Generates mitmproxy's CA (if missing).
2. **Trusts** it — installs the CA into your current-user Root store via
   `certutil`, so intercepted HTTPS validates.
3. **Redirects** traffic at the OS layer via mitmproxy's local redirector — no
   `HTTPS_PROXY`, no system-proxy toggle, no per-app configuration. mitmproxy's
   own process is always excluded so it never intercepts itself.

Just run it and use the target app. Nothing else to configure.

### Targeting specific processes

`--intercept` takes mitmproxy's local-mode process spec: a comma-separated list
of process-name substrings, each optionally prefixed with `!` to exclude. Empty
(the default) intercepts every local process. Narrowing to the client you care
about (e.g. `--intercept grok.exe`) keeps unrelated flows out of the capture dir.

### CA trust that runtimes ignore

The `certutil` step trusts the CA in the Windows Root store, which covers
browsers and most native apps. Some runtimes ship their own CA bundle and ignore
the OS store even though local mode still routes their traffic.

**Node / Electron is handled automatically.** On start the proxy bundles every
certificate under the project's `certs/` directory into a single PEM
(`~/.mitmproxy/llm-firewall-node-ca-bundle.pem`) and sets the **user-level**
`NODE_EXTRA_CA_CERTS` environment variable to point at it (restored on shutdown).
DER and PKCS#12 (`.p12`) certs are converted to PEM automatically, so dropping the
proxy CA into `certs/` is enough.

> Because it's a user-level env var, only apps **launched after** the proxy starts
> inherit it — relaunch your Electron/Node app (from the Start menu or a new
> shell; an already-open terminal keeps the old environment). Opt out with
> `--no-node-ca`, or point at a different folder with `--certs-dir <path>`.

Other runtimes still need a manual pointer at `~/.mitmproxy/mitmproxy-ca-cert.pem`:

- **Python `requests` / `httpx` / stdlib:** `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE`
- **Go:** uses the system store by default; set `SSL_CERT_FILE` only if it pins.

(Cert **pinning** defeats interception regardless of trust — the app must offer a
dev/no-pin mode.)

### Explicit-proxy mode (fallback)

The previous explicit-proxy + Windows system-proxy behaviour is still available if
you can't run elevated or local mode isn't supported on your platform:

```powershell
uv run python -m llm_firewall.run_proxy --mode regular            # 127.0.0.1:8888 + system proxy
uv run python -m llm_firewall.run_proxy --mode regular --port 8899
uv run python -m llm_firewall.run_proxy --mode regular --no-system-proxy
```

With `--no-system-proxy`, point traffic at the proxy yourself:

```powershell
$env:HTTPS_PROXY = "http://127.0.0.1:8888"
```

### Undo everything

A clean exit already restores the system proxy and `NODE_EXTRA_CA_CERTS`. To also
remove the trusted CA (and clear anything left by a hard-killed run — system proxy
and the `NODE_EXTRA_CA_CERTS` env var, if it still points at our bundle):

```powershell
uv run python -m llm_firewall.run_proxy --restore
```

### Opting out of the automation

```powershell
uv run python -m llm_firewall.run_proxy --no-trust            # don't touch the trust store
uv run python -m llm_firewall.run_proxy --no-node-ca          # don't set NODE_EXTRA_CA_CERTS
uv run python -m llm_firewall.run_proxy --no-privacy-filter   # log only, no PII redaction
```

### macOS / Linux

CA trust automation is Windows-only; on other platforms the tool prints the exact
`security` / `update-ca-certificates` commands to run. Local mode there needs
`sudo`.

> **Note:** with no `--intercept` filter, local mode captures **all** local
> traffic — expect unrelated flows in the capture dir. Narrow with `--intercept`.

## Privacy filter (PII redaction)

By default every **non-YouTube** request with a JSON body is scanned by a local
privacy-filter API (`POST http://127.0.0.1:8080/v1/filter`) before it leaves
the machine:

1. Each string value in the JSON body is sent to the filter, which returns
   byte-offset entity spans (names, emails, ...).
2. Detected entities are replaced with placeholders like `[EMAIL_1]` — the
   upstream service never sees the real values.
3. The placeholder → original mapping is cached in memory for the proxy's
   lifetime, and placeholders appearing in response bodies are swapped back,
   so the local app sees the original values — no visible difference.
   Restoration only applies to hosts that previously received a redacted
   request, so cached values can never bleed into an unrelated service's
   responses.

The same entity always maps to the same placeholder within a run, so multi-turn
LLM conversations stay coherent upstream.

**Fail-closed:** if a JSON body cannot be redacted — the filter API is down or
erroring, the body doesn't parse as JSON despite its content type, or it
exceeds the 5 MB redaction limit — the request is blocked with a local 502
(nothing unredacted leaves the machine). With `--privacy-fail-open`, requests
are forwarded instead, keeping whatever partial redaction succeeded. Flags:

| Flag | Effect |
| ---- | ------ |
| `--no-privacy-filter` | Disable redaction entirely |
| `--privacy-filter-url URL` | Filter endpoint (default `http://127.0.0.1:8080/v1/filter`) |
| `--privacy-threshold T` | Drop entity spans scoring below `T` (default `0.5`) |
| `--privacy-fail-open` | Forward unredacted instead of blocking when the filter is down |

Exempt from both redaction and restoration: `youtube.com`, `youtu.be`,
`youtube-nocookie.com`, `googlevideo.com`, `ytimg.com`, and the filter API
endpoint itself.

Notes / limitations:

- Only JSON request bodies are filtered; form/multipart/binary bodies pass
  through untouched. **WebSocket frames are not filtered** — the proxy logs a
  warning per WebSocket connection to a non-exempt host.
- Placeholders are restored in JSON, `text/*`, XML, SSE and NDJSON response
  bodies (and bodies with no content type). Responses are buffered while being
  restored, so streaming (SSE) UIs render the full answer at once rather than
  token-by-token. A placeholder split across two SSE delta events can't be
  matched and stays redacted.
- Whitespace-free blob strings (base64 images, tokens) are skipped by
  heuristic and not sent to the filter.
- The capture log records the **redacted** request for flows that went
  upstream and the restored response, plus `privacy_redactions` /
  `privacy_restored` counters per flow. A **blocked** flow (`privacy_blocked`)
  is logged with the client's original body — it never left the machine.
- The entity cache grows with the number of distinct entities seen and is
  cleared on restart.
- Because the filter API owns port 8080, the proxy's regular-mode listener
  defaults to **8888** (`--port` to change; local mode redirects at the OS
  layer and binds no port).

## Output

Captured traffic goes to `XAI_CAPTURE_DIR` (default `~/llm-firewall-capture`):

- `capture.jsonl` — one JSON record per flow (append-only, easy to grep/stream).
- `flows/<time>_<n>_<host>.json` — one pretty-printed file per flow.

Each record holds the method, URL, headers, and decoded body for both request and
response. Binary bodies are base64-encoded with `"body_is_base64": true`.

Per-flow traffic is **not printed to the terminal** — browse it in the
[review dashboard](#review-dashboard) instead. Only warnings/errors (e.g. from the
privacy filter) still reach the console.

Bodies larger than 512 KB are **not stored in full**: a big base64 payload (a
YouTube video chunk, say) becomes a short `"<N bytes binary — not logged>"`
marker, and oversized text is truncated, with `"body_truncated": true` on the
message. Without this cap, capturing everything (no `--intercept`) can grow
`capture.jsonl` to many gigabytes of video data and make the dashboard slow.
Narrow with `--intercept` to only the clients you care about.

```powershell
$env:XAI_CAPTURE_DIR = "D:\captures"
uv run python -m llm_firewall.run_proxy
```

## Review dashboard

Scrolling captured traffic in the terminal gets old fast. The dashboard serves a
searchable web UI over the same `capture.jsonl`, so you can browse flows and — for
anything the privacy filter touched — see the **before/after** of the body.

**It starts automatically with the proxy** — just open the printed URL:

```powershell
uv run python -m llm_firewall.run_proxy      # capturing + dashboard on http://127.0.0.1:8090
```

Control it with `--dashboard-port PORT` or turn it off with `--no-dashboard`. You
can also run it on its own against an existing capture (this one opens a browser
tab for you):

```powershell
uv run llm-firewall-dashboard                # standalone; opens http://127.0.0.1:8090
```

It reads the capture file live and **auto-refreshes**, so flows from a running
proxy appear on their own (or hit **Refresh**). A byte-offset cache parses only
newly appended data, so even a multi-gigabyte capture stays responsive after the
first load. Features:

- **Search** by origin/host or URL — no more scrolling the log.
- **Before/after** bodies with the changed spans highlighted: the request the
  client sent vs. what went upstream (PII → `[EMAIL_1]`), and the upstream
  response vs. what the local app saw after placeholders were restored. Flows
  with no privacy change show a single body.
- Per-flow method, status, headers, client, and redacted/restored/blocked badges.

Standalone flags: `--port` (default 8090), `--host` (default `127.0.0.1`),
`--no-browser`. It honours `XAI_CAPTURE_DIR` just like the proxy. The dashboard is
**read-only** and bound to loopback by default — captures can contain secrets, so
keep it there.

> The before/after only exists for flows the privacy filter changed. The logger
> records the client's original request body (`body_original`) alongside the
> redacted body that went upstream, and the upstream response alongside the
> restored one — present only when a redaction/restoration actually happened.

## Layout

- `llm_firewall/logger_addon.py`  — the mitmproxy addon that logs each flow.
- `llm_firewall/privacy_addon.py` — PII redaction via the privacy-filter API + response restore.
- `llm_firewall/run_proxy.py`     — launches mitmproxy in-process with the addons.
- `llm_firewall/dashboard.py`     — read-only web UI for reviewing captured flows (before/after).
- `llm_firewall/system_setup.py`  — CA trust + system-proxy automation (and undo).

The addons also work with stock mitmproxy tooling:

```powershell
uv run mitmdump -s llm_firewall/privacy_addon.py -s llm_firewall/logger_addon.py -p 8888
```
