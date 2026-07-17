"""Automatic system integration so the proxy "just works" with zero manual steps.

Two things stand between a freshly-started mitmproxy and captured HTTPS traffic:

1. The mitmproxy CA must be **trusted** by the OS, or TLS interception fails.
2. Traffic must actually be **routed** through the proxy.

This module automates both on Windows (installing the CA into the current-user
Root store via ``certutil``, and toggling the WinINET system proxy via the
registry), and prints copy-paste instructions elsewhere. Crucially, the proxy
change is reverted on shutdown so the machine isn't left pointing at a dead port.
"""

from __future__ import annotations

import logging
import platform
import subprocess
from pathlib import Path

logger = logging.getLogger("llm_firewall")

WINDOWS = platform.system() == "Windows"
CA_DIR = Path.home() / ".mitmproxy"
CA_PEM = CA_DIR / "mitmproxy-ca-cert.pem"
CA_CER = CA_DIR / "mitmproxy-ca-cert.cer"

_INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


# --------------------------------------------------------------------------- #
# CA trust
# --------------------------------------------------------------------------- #

def ca_fingerprint() -> str | None:
    """SHA-1 thumbprint (uppercase hex) of the mitmproxy CA, or None if absent."""
    if not CA_PEM.exists():
        return None
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    cert = x509.load_pem_x509_certificate(CA_PEM.read_bytes())
    return cert.fingerprint(hashes.SHA1()).hex().upper()


def is_ca_trusted() -> bool:
    """True if the mitmproxy CA is already in a trusted Root store."""
    fp = ca_fingerprint()
    if fp is None:
        return False
    if WINDOWS:
        # Check both current-user and machine Root stores.
        for scope in (["-user"], []):
            r = subprocess.run(
                ["certutil", *scope, "-verifystore", "Root", fp],
                capture_output=True,
                text=True,
            )
            if r.returncode == 0 and fp in r.stdout.upper().replace(" ", ""):
                return True
        return False
    # On non-Windows we can't cheaply verify; assume the user handled it.
    return False


def ensure_ca_trusted() -> bool:
    """Trust the mitmproxy CA if it isn't already. Returns True if trusted."""
    fp = ca_fingerprint()
    if fp is None:
        logger.warning("CA not generated yet; skipping trust step.")
        return False

    if is_ca_trusted():
        logger.info("mitmproxy CA already trusted (%s).", fp)
        return True

    if WINDOWS:
        cert = CA_CER if CA_CER.exists() else CA_PEM
        logger.info("Installing mitmproxy CA into current-user Root store...")
        r = subprocess.run(
            ["certutil", "-user", "-addstore", "-f", "Root", str(cert)],
            capture_output=True,
            text=True,
        )
        if r.returncode == 0:
            logger.info("mitmproxy CA trusted.")
            return True
        logger.error("certutil failed (%s): %s", r.returncode, r.stdout + r.stderr)
        return False

    _print_trust_instructions()
    return False


def untrust_ca() -> None:
    """Remove the mitmproxy CA from the current-user Root store (Windows)."""
    fp = ca_fingerprint()
    if not WINDOWS or fp is None:
        return
    subprocess.run(
        ["certutil", "-user", "-delstore", "Root", fp],
        capture_output=True,
        text=True,
    )
    logger.info("mitmproxy CA removed from Root store.")


def _print_trust_instructions() -> None:
    system = platform.system()
    print(">>> Trust the mitmproxy CA manually for this OS:")
    if system == "Darwin":
        print(
            "  sudo security add-trusted-cert -d -r trustRoot "
            f'-k /Library/Keychains/System.keychain "{CA_PEM}"'
        )
    elif system == "Linux":
        print(
            "  sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem "
            "/usr/local/share/ca-certificates/mitmproxy.crt "
            "&& sudo update-ca-certificates"
        )
    else:
        print(f"  Trust {CA_PEM} in your system trust store.")
    print()


# --------------------------------------------------------------------------- #
# System proxy
# --------------------------------------------------------------------------- #

def _refresh_wininet() -> None:
    """Tell WinINET-based apps to re-read proxy settings immediately."""
    import ctypes

    INTERNET_OPTION_SETTINGS_CHANGED = 39
    INTERNET_OPTION_REFRESH = 37
    wininet = ctypes.WinDLL("wininet")
    wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
    wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)


def _read_proxy_state() -> dict:
    """Snapshot the current WinINET proxy settings so they can be restored."""
    import winreg

    state: dict = {"ProxyEnable": 0, "ProxyServer": "", "ProxyOverride": ""}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INTERNET_SETTINGS) as key:
        for name in list(state):
            try:
                state[name] = winreg.QueryValueEx(key, name)[0]
            except FileNotFoundError:
                pass
    return state


def snapshot_system_proxy() -> dict:
    """Capture current proxy settings so a later :func:`restore_system_proxy` works.

    Take this snapshot *before* :func:`enable_system_proxy` so the caller holds a
    restore point even if enabling fails partway through a registry write.
    """
    if not WINDOWS:
        return {}
    return _read_proxy_state()


def enable_system_proxy(host: str, port: int) -> dict:
    """Point the Windows system proxy at host:port. Returns prior state to restore.

    If a registry write fails partway through, roll back to the pre-change state
    before re-raising so the machine is never left pointing at a dead proxy.
    """
    if not WINDOWS:
        print(f">>> Set your system/app HTTP+HTTPS proxy to {host}:{port} manually.")
        return {}

    import winreg

    previous = _read_proxy_state()
    server = f"{host}:{port}"
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, _INTERNET_SETTINGS, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, server)
            # Always let localhost/intranet bypass the proxy.
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "<local>")
    except OSError:
        # A partial write may have left the proxy half-enabled; undo it.
        restore_system_proxy(previous)
        raise
    _refresh_wininet()
    logger.info("System proxy set to %s.", server)
    return previous


def restore_system_proxy(previous: dict) -> None:
    """Restore proxy settings captured by :func:`enable_system_proxy`."""
    if not WINDOWS or not previous:
        return

    import winreg

    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER, _INTERNET_SETTINGS, 0, winreg.KEY_SET_VALUE
    ) as key:
        winreg.SetValueEx(
            key, "ProxyEnable", 0, winreg.REG_DWORD, int(previous.get("ProxyEnable", 0))
        )
        winreg.SetValueEx(
            key, "ProxyServer", 0, winreg.REG_SZ, str(previous.get("ProxyServer", ""))
        )
        winreg.SetValueEx(
            key, "ProxyOverride", 0, winreg.REG_SZ, str(previous.get("ProxyOverride", ""))
        )
    _refresh_wininet()
    logger.info("System proxy restored.")
