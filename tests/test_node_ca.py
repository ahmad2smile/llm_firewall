"""Tests for the NODE_EXTRA_CA_CERTS bundling and user-env wiring.

The certificate bundling is exercised for real (PEM, DER, and PKCS12 inputs);
the Windows registry writes are stubbed so the flow can be tested off-Windows.
"""

from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, pkcs12
from cryptography.x509.oid import NameOID

from llm_firewall import system_setup


def make_cert(cn: str):
    """A minimal self-signed cert/key pair for building test fixtures."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    import datetime

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2035, 1, 1))
        .sign(key, hashes.SHA256())
    )
    return key, cert


def test_bundle_combines_pem_der_and_p12(tmp_path: Path) -> None:
    certs_dir = tmp_path / "certs"
    certs_dir.mkdir()
    _, pem_cert = make_cert("pem-ca")
    (certs_dir / "a.pem").write_bytes(pem_cert.public_bytes(Encoding.PEM))
    _, der_cert = make_cert("der-ca")
    (certs_dir / "b.cer").write_bytes(der_cert.public_bytes(Encoding.DER))
    key, p12_cert = make_cert("p12-ca")
    (certs_dir / "c.p12").write_bytes(
        pkcs12.serialize_key_and_certificates(b"c", key, p12_cert, None, NoEncryption())
    )
    (certs_dir / "ignoreme.txt").write_text("not a cert")

    bundle = tmp_path / "bundle.pem"
    count = system_setup.build_node_ca_bundle(certs_dir, bundle)
    assert count == 3
    loaded = x509.load_pem_x509_certificates(bundle.read_bytes())
    cns = sorted(c.subject.rfc4514_string() for c in loaded)
    assert cns == ["CN=der-ca", "CN=p12-ca", "CN=pem-ca"]


def test_bundle_dedupes_identical_certs(tmp_path: Path) -> None:
    certs_dir = tmp_path / "certs"
    certs_dir.mkdir()
    _, cert = make_cert("dup-ca")
    pem = cert.public_bytes(Encoding.PEM)
    (certs_dir / "one.pem").write_bytes(pem)
    (certs_dir / "two.crt").write_bytes(pem)  # same cert, different file
    bundle = tmp_path / "bundle.pem"
    assert system_setup.build_node_ca_bundle(certs_dir, bundle) == 1


def test_bundle_empty_dir_writes_nothing(tmp_path: Path) -> None:
    certs_dir = tmp_path / "certs"
    certs_dir.mkdir()
    bundle = tmp_path / "bundle.pem"
    assert system_setup.build_node_ca_bundle(certs_dir, bundle) == 0
    assert not bundle.exists()


def test_bundle_missing_dir(tmp_path: Path) -> None:
    assert system_setup.build_node_ca_bundle(tmp_path / "nope", tmp_path / "b.pem") == 0


def test_enable_and_restore_roundtrip(tmp_path: Path, monkeypatch) -> None:
    """enable sets the var; restore returns it to the prior value."""
    certs_dir = tmp_path / "certs"
    certs_dir.mkdir()
    _, cert = make_cert("node-ca")
    (certs_dir / "ca.pem").write_bytes(cert.public_bytes(Encoding.PEM))
    bundle = tmp_path / "node-bundle.pem"
    monkeypatch.setattr(system_setup, "NODE_CA_BUNDLE", bundle)
    monkeypatch.setattr(system_setup, "WINDOWS", True)

    env: dict[str, str] = {"NODE_EXTRA_CA_CERTS": "C:/pre/existing.pem"}
    monkeypatch.setattr(system_setup, "_get_user_env", lambda n: env.get(n))
    monkeypatch.setattr(system_setup, "_set_user_env", lambda n, v: env.__setitem__(n, v))
    monkeypatch.setattr(system_setup, "_del_user_env", lambda n: env.pop(n, None))

    previous, changed = system_setup.enable_node_extra_ca_certs(certs_dir)
    assert changed is True
    assert previous == "C:/pre/existing.pem"
    assert env["NODE_EXTRA_CA_CERTS"] == str(bundle)
    assert bundle.exists()

    system_setup.restore_node_extra_ca_certs(previous)
    assert env["NODE_EXTRA_CA_CERTS"] == "C:/pre/existing.pem"


def test_enable_no_prior_value_restore_unsets(tmp_path: Path, monkeypatch) -> None:
    certs_dir = tmp_path / "certs"
    certs_dir.mkdir()
    _, cert = make_cert("node-ca")
    (certs_dir / "ca.pem").write_bytes(cert.public_bytes(Encoding.PEM))
    bundle = tmp_path / "node-bundle.pem"
    monkeypatch.setattr(system_setup, "NODE_CA_BUNDLE", bundle)
    monkeypatch.setattr(system_setup, "WINDOWS", True)

    env: dict[str, str] = {}
    monkeypatch.setattr(system_setup, "_get_user_env", lambda n: env.get(n))
    monkeypatch.setattr(system_setup, "_set_user_env", lambda n, v: env.__setitem__(n, v))
    monkeypatch.setattr(system_setup, "_del_user_env", lambda n: env.pop(n, None))

    previous, changed = system_setup.enable_node_extra_ca_certs(certs_dir)
    assert changed is True and previous is None
    assert env["NODE_EXTRA_CA_CERTS"] == str(bundle)

    system_setup.restore_node_extra_ca_certs(previous)
    assert "NODE_EXTRA_CA_CERTS" not in env


def test_enable_already_set_to_ours_is_no_change(tmp_path: Path, monkeypatch) -> None:
    certs_dir = tmp_path / "certs"
    certs_dir.mkdir()
    _, cert = make_cert("node-ca")
    (certs_dir / "ca.pem").write_bytes(cert.public_bytes(Encoding.PEM))
    bundle = tmp_path / "node-bundle.pem"
    monkeypatch.setattr(system_setup, "NODE_CA_BUNDLE", bundle)
    monkeypatch.setattr(system_setup, "WINDOWS", True)

    env = {"NODE_EXTRA_CA_CERTS": str(bundle)}  # left over from a prior run
    monkeypatch.setattr(system_setup, "_get_user_env", lambda n: env.get(n))
    monkeypatch.setattr(system_setup, "_set_user_env", lambda n, v: env.__setitem__(n, v))

    previous, changed = system_setup.enable_node_extra_ca_certs(certs_dir)
    # Already ours: don't treat it as a change (so we won't clobber on restore).
    assert changed is False
