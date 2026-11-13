"""Container / service health check: exit 0 when the dashboard answers on this machine.

    python -m ghostap.healthcheck [port]

Tries HTTPS first (a self-signed certificate is accepted: this only checks that the
local server is alive), then plain HTTP. /api/login/state needs no sign-in.
"""
from __future__ import annotations

import ssl
import sys
import urllib.request


def alive(port: int = 8050, timeout: float = 4.0) -> bool:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE           # local liveness only, never used for data
    for url, kw in (("https://127.0.0.1:{}/api/login/state", {"context": ctx}),
                    ("http://127.0.0.1:{}/api/login/state", {})):
        try:
            with urllib.request.urlopen(url.format(port), timeout=timeout, **kw) as r:  # noqa: S310 - fixed local URL
                if r.status == 200:
                    return True
        except OSError:
            continue
    return False


if __name__ == "__main__":
    sys.exit(0 if alive(int(sys.argv[1]) if len(sys.argv) > 1 else 8050) else 1)
