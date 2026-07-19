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

# Node/Electron runtimes ship their own CA bundle and ignore the OS Root store,
# so trusting the mitmproxy CA there means pointing NODE_EXTRA_CA_CERTS at a PEM
# file. That variable takes a single file, so we bundle every cert under the
# project's certs/ dir into one PEM (kept next to the CA, outside the repo).
NODE_CA_ENV = "NODE_EXTRA_CA_CERTS"
NODE_CA_BUNDLE = CA_DIR / "llm-firewall-node-ca-bundle.pem"
_USER_ENV_SUBKEY = "Environment"  # HKCU\Environment holds user-level env vars
_CERT_SUFFIXES = {".pem", ".crt", ".cer", ".der", ".p12", ".pfx"}


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


# --------------------------------------------------------------------------- #
# NODE_EXTRA_CA_CERTS (user-level env var for Node/Electron trust)
# --------------------------------------------------------------------------- #

def _pem_certs_from_file(path: Path) -> list[bytes]:
    """Return each certificate in a file as a PEM block (converting DER/PKCS12)."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding, pkcs12

    data = path.read_bytes()
    try:
        if path.suffix.lower() in (".p12", ".pfx"):
            # CA-only exports keep the cert in additional_certificates, so take
            # both the main cert (if any) and the extras.
            _key, cert, extra = pkcs12.load_key_and_certificates(data, None)
            certs = ([cert] if cert else []) + list(extra or [])
        elif b"-----BEGIN CERTIFICATE-----" in data:
            certs = x509.load_pem_x509_certificates(data)  # may hold several
        else:
            certs = [x509.load_der_x509_certificate(data)]
        return [c.public_bytes(Encoding.PEM) for c in certs]
    except Exception as exc:
        logger.warning("skipping %s (not a readable certificate): %s", path.name, exc)
        return []


def build_node_ca_bundle(certs_dir: Path, bundle_path: Path | None = None) -> int:
    """Concatenate every cert under ``certs_dir`` into one PEM bundle.

    Returns the number of unique certificates written (0 if none were found, in
    which case no bundle file is created).
    """
    if bundle_path is None:
        bundle_path = NODE_CA_BUNDLE
    if not certs_dir.is_dir():
        logger.warning("certs dir %s not found; NODE_EXTRA_CA_CERTS not set", certs_dir)
        return 0
    seen: set[bytes] = set()
    pems: list[bytes] = []
    for path in sorted(certs_dir.iterdir()):
        if not path.is_file() or path.suffix.lower() not in _CERT_SUFFIXES:
            continue
        for pem in _pem_certs_from_file(path):
            norm = pem.strip()
            if norm and norm not in seen:
                seen.add(norm)
                pems.append(norm)
    if not pems:
        return 0
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    bundle_path.write_bytes(b"\n".join(pems) + b"\n")
    return len(pems)


def _get_user_env(name: str) -> str | None:
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _USER_ENV_SUBKEY) as key:
            return winreg.QueryValueEx(key, name)[0]
    except FileNotFoundError:
        return None


def _set_user_env(name: str, value: str) -> None:
    import winreg

    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER, _USER_ENV_SUBKEY, 0, winreg.KEY_SET_VALUE
    ) as key:
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
    _broadcast_env_change()


def _del_user_env(name: str) -> None:
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, _USER_ENV_SUBKEY, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.DeleteValue(key, name)
    except FileNotFoundError:
        return
    _broadcast_env_change()


def _broadcast_env_change() -> None:
    """Notify Explorer so processes launched afterwards inherit the new value.

    A user-level env var written to the registry is only seen by processes that
    start *after* this broadcast (an already-open shell keeps its old copy).
    """
    import ctypes

    HWND_BROADCAST = 0xFFFF
    WM_SETTINGCHANGE = 0x001A
    SMTO_ABORTIFHUNG = 0x0002
    result = ctypes.c_ulong()
    ctypes.windll.user32.SendMessageTimeoutW(
        HWND_BROADCAST,
        WM_SETTINGCHANGE,
        0,
        ctypes.c_wchar_p(_USER_ENV_SUBKEY),
        SMTO_ABORTIFHUNG,
        5000,
        ctypes.byref(result),
    )


def enable_node_extra_ca_certs(certs_dir: Path) -> tuple[str | None, bool]:
    """Point NODE_EXTRA_CA_CERTS at a bundle of ``certs_dir``'s certificates.

    Returns ``(previous_value, changed)``. When ``changed`` is True the caller
    must pass ``previous_value`` to :func:`restore_node_extra_ca_certs` at
    shutdown. A no-op (returns ``(None, False)``) when no certs are found or on
    non-Windows, where the export line is printed instead.
    """
    count = build_node_ca_bundle(certs_dir)
    if count == 0:
        return None, False
    if not WINDOWS:
        print(
            f'>>> For Node/Electron apps, run: export {NODE_CA_ENV}="{NODE_CA_BUNDLE}"'
        )
        return None, False
    previous = _get_user_env(NODE_CA_ENV)
    if previous == str(NODE_CA_BUNDLE):
        # A prior run left it set (e.g. hard-killed before restore); treat as
        # unchanged so we don't later "restore" our own bundle as the baseline.
        logger.info("%s already set to %s (%d cert(s)).", NODE_CA_ENV, NODE_CA_BUNDLE, count)
        return previous, False
    _set_user_env(NODE_CA_ENV, str(NODE_CA_BUNDLE))
    logger.info("%s set to %s (%d cert(s)).", NODE_CA_ENV, NODE_CA_BUNDLE, count)
    return previous, True


def restore_node_extra_ca_certs(previous: str | None) -> None:
    """Undo :func:`enable_node_extra_ca_certs`, restoring any prior value."""
    if not WINDOWS:
        return
    if previous is None:
        _del_user_env(NODE_CA_ENV)
    else:
        _set_user_env(NODE_CA_ENV, previous)
    logger.info("%s restored.", NODE_CA_ENV)


def clear_node_extra_ca_certs() -> None:
    """Best-effort teardown for ``--restore``: drop the var if it's ours, delete bundle."""
    if WINDOWS and _get_user_env(NODE_CA_ENV) == str(NODE_CA_BUNDLE):
        _del_user_env(NODE_CA_ENV)
        logger.info("%s cleared.", NODE_CA_ENV)
    try:
        NODE_CA_BUNDLE.unlink()
    except FileNotFoundError:
        pass
