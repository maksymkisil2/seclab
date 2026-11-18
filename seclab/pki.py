"""Per-lab PKI via the openssl CLI: ECDSA P-384 CA -> ECDSA P-256 server cert."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

SERVER_EXT = (
    "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
    "basicConstraints=critical,CA:FALSE\n"
    "keyUsage=critical,digitalSignature\n"
    "extendedKeyUsage=serverAuth\n"
)


def _openssl(*args: str, cwd: Path) -> None:
    binary = shutil.which("openssl")
    if not binary:
        raise RuntimeError("openssl CLI not found in PATH (needed for lab certificates)")
    proc = subprocess.run([binary, *args], cwd=cwd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"openssl {args[0]} failed: {proc.stderr.strip()}")


def ensure_pki(tls_dir: Path) -> None:
    if (tls_dir / "server.crt").exists() and (tls_dir / "server.key").exists():
        return
    tls_dir.mkdir(parents=True, exist_ok=True)
    _openssl("ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", "ca.key", cwd=tls_dir)
    _openssl(
        "req", "-x509", "-new", "-key", "ca.key", "-sha384", "-days", "825",
        "-subj", "/CN=seclab Lab CA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-out", "ca.crt", cwd=tls_dir,
    )
    _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "server.key", cwd=tls_dir)
    _openssl("req", "-new", "-key", "server.key", "-subj", "/CN=localhost", "-out", "server.csr", cwd=tls_dir)
    (tls_dir / "server.ext").write_text(SERVER_EXT)
    _openssl(
        "x509", "-req", "-in", "server.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
        "-days", "397", "-sha256", "-extfile", "server.ext", "-out", "server.crt", cwd=tls_dir,
    )
    for tmp in ("server.csr", "server.ext", "ca.srl"):
        (tls_dir / tmp).unlink(missing_ok=True)
    os.chmod(tls_dir / "ca.key", 0o600)
    # Lab-only key: container user (uid 101) must read it through a single-file bind mount.
    os.chmod(tls_dir / "server.key", 0o644)
