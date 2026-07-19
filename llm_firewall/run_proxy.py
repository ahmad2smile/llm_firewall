"""Run the mitmproxy logging proxy in OS-level **local (transparent)** mode.

Local mode redirects traffic at the network layer (WinDivert on Windows), so
clients are intercepted even when they ignore proxy settings — which is exactly
the case for Electron / Node / Python / Go clients that only honour ``HTTPS_PROXY``
or nothing at all. There is **no** ``HTTPS_PROXY`` to set and **no** system-proxy
registry toggle: the redirector captures the target processes directly.

Usage:
    python -m llm_firewall.run_proxy                       # intercept everything
    python -m llm_firewall.run_proxy --intercept grok.exe  # only these processes
    python -m llm_firewall.run_proxy --intercept "node,python.exe"
    python -m llm_firewall.run_proxy --intercept "!chrome.exe"   # all but Chrome
    python -m llm_firewall.run_proxy --mode regular        # old explicit-proxy path
    python -m llm_firewall.run_proxy --no-node-ca          # don't set NODE_EXTRA_CA_CERTS
    python -m llm_firewall.run_proxy --restore             # undo trust + proxy + node CA, exit

``--intercept`` takes mitmproxy's local-mode process spec: a comma-separated list
of process-name substrings, each optionally prefixed with ``!`` to exclude. Empty
means intercept all local processes (mitmproxy's own process is always excluded).

Unless ``--no-privacy-filter`` is given, JSON request bodies to non-YouTube hosts
are PII-redacted through a local privacy-filter API before leaving the machine,
and the redactions are transparently undone in response bodies — see
``privacy_addon.py``. The filter owns port 8080, so the regular-mode listener
defaults to 8888 (local mode redirects at the OS layer and binds no port).

A read-only review dashboard is served alongside the proxy at
http://127.0.0.1:8090 (``--dashboard-port`` to change, ``--no-dashboard`` to
disable) — a searchable UI over the capture with before/after bodies. See
``dashboard.py``.

Note (Windows): local mode uses WinDivert and requires an **elevated** (admin)
process. Run your terminal as Administrator, or the redirector will fail to start.

Environment:
    XAI_CAPTURE_DIR   Directory for captured traffic (default ~/llm-firewall-capture)
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
from pathlib import Path

from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

from llm_firewall import dashboard, system_setup
from llm_firewall.logger_addon import RequestLogger, capture_dir
from llm_firewall.privacy_addon import DEFAULT_FILTER_URL, DEFAULT_THRESHOLD, PrivacyFilter

logger = logging.getLogger("llm_firewall")
CA_CERT = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
# Certificates bundled into NODE_EXTRA_CA_CERTS live in the repo's certs/ dir.
CERTS_DIR = Path(__file__).resolve().parent.parent / "certs"


def _setup_logging() -> None:
    """Isolate our logger from mitmproxy's root handler.

    mitmproxy attaches a handler to the root logger that forwards records to its
    event loop. After the proxy shuts down that loop is closed, so any teardown
    logging that propagates to root would raise ``Event loop is closed``. Giving
    our logger its own handler with ``propagate = False`` keeps teardown safe.
    """
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    logger.propagate = False


def _is_admin() -> bool:
    """True if the current process has the privileges local mode needs."""
    if system_setup.WINDOWS:
        import ctypes

        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    # POSIX: WinDivert isn't used; the rust redirector needs root there instead.
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _local_mode_spec(intercept: str) -> str:
    """Build mitmproxy's ``local`` mode string from an intercept spec."""
    intercept = intercept.strip()
    return f"local:{intercept}" if intercept else "local"


async def _run(
    proxy_modes: list[str], host: str, port: int, privacy: PrivacyFilter | None
) -> None:
    opts = options.Options(listen_host=host, listen_port=port, mode=proxy_modes)
    # with_termlog=False: no per-flow / mitmproxy chatter in the terminal — all
    # traffic is reviewed in the dashboard instead.
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    # Privacy first: it must redact before the request leaves and restore the
    # response before the logger records it.
    if privacy is not None:
        master.addons.add(privacy)
    master.addons.add(RequestLogger())

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, master.shutdown)
        except NotImplementedError:
            signal.signal(sig, lambda *_: master.shutdown())

    await master.run()


def main(argv: list[str] | None = None) -> int:
    _setup_logging()

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=("local", "regular"),
        default="local",
        help="local = OS-level transparent redirect (default); "
        "regular = explicit proxy + system-proxy toggle",
    )
    parser.add_argument(
        "--intercept",
        default="",
        metavar="SPEC",
        help="local mode only: process filter, e.g. 'grok.exe', 'node,python.exe', "
        "'!chrome.exe'. Empty = all processes.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Listen host (regular mode)")
    parser.add_argument(
        "--port",
        type=int,
        default=8888,
        help="Proxy listen port for regular mode (default 8888 — 8080 is left to "
        "the privacy-filter API). Local mode redirects at the OS layer and does "
        "not bind this port.",
    )
    parser.add_argument(
        "--no-privacy-filter",
        action="store_true",
        help="Disable PII redaction via the privacy-filter API",
    )
    parser.add_argument(
        "--privacy-filter-url",
        default=DEFAULT_FILTER_URL,
        metavar="URL",
        help="privacy-filter endpoint (default %(default)s)",
    )
    parser.add_argument(
        "--privacy-threshold",
        type=float,
        default=DEFAULT_THRESHOLD,
        metavar="T",
        help="drop entity spans scoring below T (default %(default)s)",
    )
    parser.add_argument(
        "--privacy-fail-open",
        action="store_true",
        help="If the filter API is down, forward requests UNREDACTED instead of "
        "blocking them with a 502",
    )
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Don't start the review dashboard alongside the proxy",
    )
    parser.add_argument(
        "--dashboard-port",
        type=int,
        default=dashboard.DEFAULT_PORT,
        metavar="PORT",
        help="Port for the review dashboard (default %(default)s, loopback only)",
    )
    parser.add_argument(
        "--no-trust", action="store_true", help="Don't install/trust the mitmproxy CA"
    )
    parser.add_argument(
        "--no-system-proxy",
        action="store_true",
        help="regular mode only: don't change the OS system proxy",
    )
    parser.add_argument(
        "--no-node-ca",
        action="store_true",
        help="Don't set the user-level NODE_EXTRA_CA_CERTS env var for Node/Electron",
    )
    parser.add_argument(
        "--certs-dir",
        default=str(CERTS_DIR),
        metavar="DIR",
        help="Directory of certificates bundled into NODE_EXTRA_CA_CERTS "
        "(default %(default)s)",
    )
    parser.add_argument(
        "--restore",
        action="store_true",
        help="Undo CA trust + system proxy + NODE_EXTRA_CA_CERTS, then exit",
    )
    args = parser.parse_args(argv)

    if args.restore:
        system_setup.restore_system_proxy(_saved_or_default())
        system_setup.untrust_ca()
        system_setup.clear_node_extra_ca_certs()
        print(
            ">>> Restored: system proxy cleared, mitmproxy CA untrusted, "
            "NODE_EXTRA_CA_CERTS unset."
        )
        return 0

    privacy: PrivacyFilter | None = None
    if not args.no_privacy_filter:
        privacy = PrivacyFilter(
            filter_url=args.privacy_filter_url,
            threshold=args.privacy_threshold,
            fail_open=args.privacy_fail_open,
        )
        # Only a real bind conflict is refused: regular mode binding the port a
        # LOCAL filter already holds. Local mode never binds --port, and a
        # remote filter can share a port number with the local listener.
        if (
            args.mode == "regular"
            and args.port == privacy.filter_port
            and privacy.filter_host in ("127.0.0.1", "localhost", "::1")
        ):
            logger.error(
                "--port %s collides with the local privacy-filter API port. Pick "
                "another proxy port (default 8888) or use --no-privacy-filter.",
                args.port,
            )
            return 1

    capture_path = capture_dir()

    # Generate the CA up front (via a throwaway master) so we can trust it
    # *before* traffic starts flowing.
    if not CA_CERT.exists():
        logger.info("Generating mitmproxy CA at %s ...", CA_CERT)
        asyncio.run(_generate_ca(args.host, args.port))

    if not args.no_trust:
        system_setup.ensure_ca_trusted()

    # Point Node/Electron runtimes (which ignore the OS Root store) at a PEM
    # bundle of the project's certs. Set as a user-level env var so apps launched
    # afterwards inherit it; restored on shutdown.
    node_ca_prev: str | None = None
    node_ca_changed = False
    if not args.no_node_ca:
        node_ca_prev, node_ca_changed = system_setup.enable_node_extra_ca_certs(
            Path(args.certs_dir)
        )

    if args.mode == "local":
        if not _is_admin():
            elevate = (
                "Run your terminal as Administrator"
                if system_setup.WINDOWS
                else "Re-run with sudo"
            )
            logger.error(
                "Local (transparent) mode needs elevated privileges to redirect "
                "traffic. %s, or use --mode regular. Aborting.",
                elevate,
            )
            return 1
        proxy_modes = [_local_mode_spec(args.intercept)]
        target = args.intercept or "all local processes"
        print(
            f">>> Local transparent capture live, intercepting {target} "
            f"(Ctrl-C to stop). Capture dir: {capture_path}"
        )
        # Local mode redirects at the OS layer: no system proxy to set or revert.
        previous_proxy: dict = {}
    else:
        proxy_modes = ["regular"]
        previous_proxy = {}
        if not args.no_system_proxy:
            # Snapshot before enabling so the finally block can restore even if
            # enable_system_proxy fails partway through.
            previous_proxy = system_setup.snapshot_system_proxy()
            system_setup.enable_system_proxy(args.host, args.port)
        print(
            f">>> Capture proxy live on {args.host}:{args.port} (Ctrl-C to stop). "
            f"Capture dir: {capture_path}"
        )

    if privacy is not None:
        print(
            f">>> Privacy filter: ON via {args.privacy_filter_url} "
            f"({'fail-open' if args.privacy_fail_open else 'fail-closed'}; "
            f"YouTube exempt)"
        )
    else:
        print(">>> Privacy filter: OFF (--no-privacy-filter)")

    if not args.no_node_ca and system_setup.NODE_CA_BUNDLE.exists():
        print(
            f">>> Node/Electron trust: {system_setup.NODE_CA_ENV} -> "
            f"{system_setup.NODE_CA_BUNDLE} (relaunch those apps to pick it up)"
        )

    # Serve the review dashboard alongside the proxy so captured flows can be
    # browsed live. A failure here (e.g. port in use) must not stop capturing.
    dashboard_server = None
    if not args.no_dashboard:
        try:
            dashboard_server = dashboard.serve_background(
                "127.0.0.1", args.dashboard_port, capture_path / "capture.jsonl"
            )
            print(
                f">>> Review dashboard: http://127.0.0.1:{args.dashboard_port}/ "
                f"(search + before/after)"
            )
        except OSError as exc:
            logger.warning(
                "review dashboard not started on port %s (%s); capturing anyway. "
                "Use --dashboard-port <other> or --no-dashboard.",
                args.dashboard_port,
                exc,
            )

    rc = 0
    try:
        asyncio.run(_run(proxy_modes, args.host, args.port, privacy))
    except KeyboardInterrupt:
        pass
    except SystemExit as e:
        rc = e.code if isinstance(e.code, int) else 1
        logger.error(
            "Proxy exited early. In local mode this usually means WinDivert "
            "couldn't start (not elevated?); in regular mode, port %s may be in "
            "use (try --port <other>).",
            args.port,
        )
    finally:
        # Always undo any system-proxy change so the machine keeps working.
        system_setup.restore_system_proxy(previous_proxy)
        if node_ca_changed:
            system_setup.restore_node_extra_ca_certs(node_ca_prev)
        if dashboard_server is not None:
            dashboard_server.shutdown()
            dashboard_server.server_close()

    return rc


async def _generate_ca(host: str, port: int) -> None:
    """Start and immediately stop a master so mitmproxy writes its CA files."""
    opts = options.Options(listen_host=host, listen_port=0)
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)

    async def _stop() -> None:
        await asyncio.sleep(1.5)
        master.shutdown()

    asyncio.create_task(_stop())
    try:
        await master.run()
    except Exception:
        pass


def _saved_or_default() -> dict:
    """Best-effort default for --restore: disable proxy entirely."""
    return {"ProxyEnable": 0, "ProxyServer": "", "ProxyOverride": ""}


if __name__ == "__main__":
    sys.exit(main())
