# llm-firewall

A TLS-intercepting logging proxy built on [mitmproxy](https://mitmproxy.org/).
It runs in mitmproxy's **local (transparent) mode**, redirecting traffic at the
OS layer (WinDivert on Windows) and logging every request/response to disk.
Because interception happens at the network layer, clients are captured even when
they ignore proxy settings — including **Electron / Node / Python / Go** clients
that only honour `HTTPS_PROXY`, or nothing at all.

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
the OS store even though local mode still routes their traffic — for those, point
them at `~/.mitmproxy/mitmproxy-ca-cert.pem`:

- **Node / Electron main process:** `NODE_EXTRA_CA_CERTS=<path>`
- **Python `requests` / `httpx` / stdlib:** `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE`
- **Go:** uses the system store by default; set `SSL_CERT_FILE` only if it pins.

(Cert **pinning** defeats interception regardless of trust — the app must offer a
dev/no-pin mode.)

### Explicit-proxy mode (fallback)

The previous explicit-proxy + Windows system-proxy behaviour is still available if
you can't run elevated or local mode isn't supported on your platform:

```powershell
uv run python -m llm_firewall.run_proxy --mode regular            # 127.0.0.1:8080 + system proxy
uv run python -m llm_firewall.run_proxy --mode regular --port 8899
uv run python -m llm_firewall.run_proxy --mode regular --no-system-proxy
```

With `--no-system-proxy`, point traffic at the proxy yourself:

```powershell
$env:HTTPS_PROXY = "http://127.0.0.1:8080"
```

### Undo everything

Local mode changes no persistent network settings, so a clean exit leaves nothing
to revert. To remove the trusted CA (and clear any system proxy left by a hard-killed
`--mode regular` run):

```powershell
uv run python -m llm_firewall.run_proxy --restore
```

### Opting out of the automation

```powershell
uv run python -m llm_firewall.run_proxy --no-trust          # don't touch the trust store
```

### macOS / Linux

CA trust automation is Windows-only; on other platforms the tool prints the exact
`security` / `update-ca-certificates` commands to run. Local mode there needs
`sudo`.

> **Note:** with no `--intercept` filter, local mode captures **all** local
> traffic — expect unrelated flows in the capture dir. Narrow with `--intercept`.

## Output

Captured traffic goes to `XAI_CAPTURE_DIR` (default `~/llm-firewall-capture`):

- `capture.jsonl` — one JSON record per flow (append-only, easy to grep/stream).
- `flows/<time>_<n>_<host>.json` — one pretty-printed file per flow.

Each record holds the method, URL, headers, and decoded body for both request and
response. Binary bodies are base64-encoded with `"body_is_base64": true`.

```powershell
$env:XAI_CAPTURE_DIR = "D:\captures"
uv run python -m llm_firewall.run_proxy
```

## Layout

- `llm_firewall/logger_addon.py` — the mitmproxy addon that logs each flow.
- `llm_firewall/run_proxy.py`    — launches mitmproxy in-process with the addon.
- `llm_firewall/system_setup.py` — CA trust + system-proxy automation (and undo).

The addon also works with stock mitmproxy tooling:

```powershell
uv run mitmdump -s llm_firewall/logger_addon.py -p 8080
```
