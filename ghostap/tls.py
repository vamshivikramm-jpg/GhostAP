"""HTTPS mode (F064).

    python -m ghostap.web --iface wlan0mon --host 0.0.0.0 --https            # self-signed
    python -m ghostap.web ... --tls-cert fullchain.pem --tls-key privkey.pem   # your own

A self-signed certificate is made once with the `openssl` command in data/tls/ (key file
readable only by you) and reused. Browsers warn about it the first time: compare the
SHA-256 fingerprint GhostAP prints with the one the browser shows before accepting it.
"""
from __future__ import annotations

import ipaddress
import os
import shutil
import socket
import subprocess
from typing import Iterable, Tuple

TLS_DIR = os.path.join("data", "tls")


class TLSError(RuntimeError):
    pass


def _openssl() -> str:
    exe = shutil.which("openssl")
    if not exe:
        raise TLSError("the openssl command is not installed (Kali: it is; macOS: brew install openssl), "
                       "or pass --tls-cert and --tls-key")
    return exe


def fingerprint(cert: str) -> str:
    out = subprocess.run([_openssl(), "x509", "-in", cert, "-noout", "-fingerprint", "-sha256"],
                         check=True, capture_output=True, text=True).stdout.strip()
    return out.split("=", 1)[-1]


def self_signed(hosts: Iterable[str] = (), directory: str = TLS_DIR) -> Tuple[str, str]:
    """(cert, key) paths, creating them the first time."""
    cert, key = os.path.join(directory, "ghostap-cert.pem"), os.path.join(directory, "ghostap-key.pem")
    if os.path.exists(cert) and os.path.exists(key):
        return cert, key
    os.makedirs(directory, exist_ok=True)
    names = {"localhost", socket.gethostname()} | {h for h in hosts if h and h not in ("0.0.0.0", "::")}  # noqa: S104
    san = []
    for n in sorted(names):
        try:
            ipaddress.ip_address(n)
            san.append("IP:" + n)
        except ValueError:
            san.append("DNS:" + n)
    san += ["IP:127.0.0.1", "IP:::1"]
    old = os.umask(0o077)                     # the key file is created readable only by its owner
    try:
        subprocess.run([_openssl(), "req", "-x509", "-newkey", "rsa:3072", "-sha256", "-days", "397", "-nodes",
                        "-keyout", key, "-out", cert, "-subj", "/CN=GhostAP dashboard",
                        "-addext", "subjectAltName=" + ",".join(dict.fromkeys(san))],
                       check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        raise TLSError("openssl could not create a certificate: " + (e.stderr or "").strip()[-300:]) from None
    finally:
        os.umask(old)
    return cert, key


def check_pair(cert: str, key: str) -> None:
    for p in (cert, key):
        if not os.path.isfile(p):
            raise TLSError("{} does not exist".format(p))
    import ssl
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    try:
        ctx.load_cert_chain(cert, key)
    except (ssl.SSLError, OSError) as e:
        raise TLSError("the certificate and key do not work together: {}".format(e)) from None
