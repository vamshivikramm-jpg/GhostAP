"""Dashboard files: install-as-app manifest (F081), translations (F082), CSP-safe markup."""
import json
import os
import re
import tempfile

from ghostap.config import load_config
from ghostap.web import create_app

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(ROOT, "ghostap", "static")


def _client():
    db = os.path.join(tempfile.mkdtemp(), "x.db")
    return create_app(db, load_config(os.path.join(ROOT, "config.yaml")), admin_db=db + ".a").test_client()


def test_manifest_and_icons_are_served():
    c = _client()
    r = c.get("/manifest.webmanifest")
    assert r.status_code == 200 and r.mimetype == "application/manifest+json"
    m = json.loads(r.data)
    assert m["start_url"] == "/" and m["display"] == "standalone"
    for icon in m["icons"]:
        got = c.get(icon["src"])
        assert got.status_code == 200 and got.mimetype == "image/png", icon["src"]
    assert c.get("/static/icons/apple-touch-icon.png").status_code == 200
    # no service worker: an installed dashboard is never served from a stale cache
    assert not any(f.endswith("sw.js") or "service" in f for f in os.listdir(STATIC))


def test_page_scripts_exist_and_nothing_inline():
    html = open(os.path.join(STATIC, "index.html"), encoding="utf-8").read()
    scripts = re.findall(r"<script([^>]*)>", html)
    assert scripts and all('src="' in s for s in scripts), "inline <script> would break the CSP"
    assert "onclick=" not in html and "onload=" not in html
    c = _client()
    for src in re.findall(r'<script src="([^"]+)"', html):
        assert c.get(src).status_code == 200, src
    for f in os.listdir(STATIC):
        if f.endswith(".js"):
            assert "eval(" not in open(os.path.join(STATIC, f), encoding="utf-8").read(), f


def test_translation_keys_match_the_markup():
    html = open(os.path.join(STATIC, "index.html"), encoding="utf-8").read()
    i18n = open(os.path.join(STATIC, "i18n.js"), encoding="utf-8").read()
    used = set(re.findall(r'data-i18n="([^"]+)"', html))
    for lang in ("hi", "te"):
        block = i18n.split("    {}: {{".format(lang), 1)[1].split("\n    },", 1)[0]
        keys = set(re.findall(r'"([a-z]+(?:\.[a-z]+)?)":', block))
        assert used <= keys, (lang, used - keys)
    assert "draft" in i18n.lower()                      # labelled as unreviewed
