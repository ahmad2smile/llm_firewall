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
    python -m llm_firewall.run_proxy --restore             # undo trust + proxy, exit

``--intercept`` takes mitmproxy's local-mode process spec: a comma-separated list
of process-name substrings, each optionally prefixed with ``!`` to exclude. Empty
means intercept all local processes (mitmproxy's own process is always excluded).

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

from llm_firewall import system_setup
from llm_firewall.logger_addon import RequestLogger, capture_dir

logger = logging.getLogger("llm_firewall")
CA_CERT = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"


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


async def _run(proxy_modes: list[str], host: str, port: int) -> None:
    opts = options.Options(listen_host=host, listen_port=port, mode=proxy_modes)
    master = DumpMaster(opts, with_termlog=True, with_dumper=False)
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
    parser.add_argument("--port", type=int, default=8080, help="Listen port (regular mode)")
    parser.add_argument(
        "--no-trust", action="store_true", help="Don't install/trust the mitmproxy CA"
    )
    parser.add_argument(
        "--no-system-proxy",
        action="store_true",
        help="regular mode only: don't change the OS system proxy",
    )
    parser.add_argument(
        "--restore",
        action="store_true",
        help="Undo CA trust + system proxy, then exit",
    )
    args = parser.parse_args(argv)

    if args.restore:
        system_setup.restore_system_proxy(_saved_or_default())
        system_setup.untrust_ca()
        print(">>> Restored: system proxy cleared, mitmproxy CA untrusted.")
        return 0

    capture_path = capture_dir()

    # Generate the CA up front (via a throwaway master) so we can trust it
    # *before* traffic starts flowing.
    if not CA_CERT.exists():
        logger.info("Generating mitmproxy CA at %s ...", CA_CERT)
        asyncio.run(_generate_ca(args.host, args.port))

    if not args.no_trust:
        system_setup.ensure_ca_trusted()

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

    rc = 0
    try:
        asyncio.run(_run(proxy_modes, args.host, args.port))
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
