"""GhostAP 2.0 Phase 0: fixes for audit findings S1 (cross-site requests), S2 (what
viewers can read) and S3 (paths inside imported session bundles)."""
import json
import os
import zipfile

import pytest

from ghostap import apikeys
from ghostap.auth import Auth
from ghostap.config import load_config
from ghostap.sessions import SessionStore, export_bundle, import_bundle, is_pcap, recording_of
from ghostap.web import create_app

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(ROOT, "config.yaml")
PW = "correct horse battery"


@pytest.fixture()
def local(tmp_path):
    admin = str(tmp_path / "a.db")
    app = create_app(str(tmp_path / "s.db"), load_config(CONFIG), admin_db=admin, config_path=CONFIG)
    return app.test_client(), admin


# ---------------------------------------------------------------- S1
@pytest.mark.parametrize("headers", [
    {"Sec-Fetch-Site": "cross-site"},
    {"Sec-Fetch-Site": "same-site"},
    {"Origin": "https://evil.example"},
    {"Origin": "null"},
])
def test_cross_site_posts_are_refused_even_without_accounts(local, headers):
    c, admin = local
    kid, _ = apikeys.create(admin, "victim", "read")
    r = c.post("/api/keys/{}/revoke".format(kid), json={}, headers=headers)
    assert r.status_code == 403
    assert c.get("/api/keys").get_json()[0]["revoked"] is None          # nothing happened


def test_form_posts_need_json_and_same_origin_works(local):
    c, admin = local
    kid, _ = apikeys.create(admin, "k", "read")
    form = c.post("/api/keys/{}/revoke".format(kid), data="x=1",
                  headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert form.status_code == 415
    plain = c.post("/api/keys/{}/revoke".format(kid), data="{}", headers={"Content-Type": "text/plain"})
    assert plain.status_code == 415
    ok = c.post("/api/keys/{}/revoke".format(kid), json={},
                headers={"Sec-Fetch-Site": "same-origin", "Origin": "http://localhost"})
    assert ok.status_code == 200
    # a script (curl / sensor) sends neither header: still works
    kid2, _ = apikeys.create(admin, "k2", "read")
    assert c.post("/api/keys/{}/revoke".format(kid2), json={}).status_code == 200
    assert c.get("/api/summary", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 200   # reads unaffected


# ---------------------------------------------------------------- S2
def test_viewers_cannot_read_config_audit_or_notification_targets(tmp_path):
    import yaml
    cfg = load_config(CONFIG)
    cfg["notifications"]["webhooks"] = [{"name": "x", "url": "https://hooks.example/SECRET-TOKEN", "format": "json"}]
    cfgfile = tmp_path / "c.yaml"
    yaml.safe_dump(cfg, open(cfgfile, "w"))
    admin = str(tmp_path / "a.db")
    app = create_app(str(tmp_path / "s.db"), cfg, admin_db=admin, config_path=str(cfgfile))
    au = Auth(admin)
    for name, role in (("boss", "admin"), ("ana", "analyst"), ("vic", "viewer")):
        au.add_user(name, PW, role)
    app.extensions["ghostap"].gate.auth._count_cache = (0.0, -1)
    clients = {}
    for name in ("boss", "ana", "vic"):
        c = app.test_client()
        assert c.post("/api/login", json={"username": name, "password": PW}).status_code == 200
        clients[name] = c
    vic, ana, boss = clients["vic"], clients["ana"], clients["boss"]
    for url in ("/api/settings/effective", "/api/audit", "/api/notifications"):
        r = vic.get(url)
        assert r.status_code == 403 and "SECRET-TOKEN" not in r.get_data(as_text=True), url
    assert ana.get("/api/settings/effective").status_code == 403                    # admins only
    assert ana.get("/api/audit").status_code == 200 and ana.get("/api/notifications").status_code == 200
    assert boss.get("/api/settings/effective").status_code == 200
    assert vic.get("/api/summary").status_code == 200                             # normal reading still fine


# ---------------------------------------------------------------- S3
def test_imported_bundle_cannot_point_at_other_files(tmp_path):
    store = SessionStore(str(tmp_path / "sessions"))
    pcap = os.path.join(ROOT, "data", "test_capture.pcap")
    if not os.path.exists(pcap):
        import sys
        sys.path.insert(0, os.path.join(ROOT, "tools"))
        import make_test_pcap
        make_test_pcap.generate(os.path.join(ROOT, "data"))
    s = store.create("orig", "replay", pcap)
    open(s.db, "wb").close()
    assert recording_of(s) == pcap and is_pcap(pcap)
    secret = tmp_path / "private.txt"
    secret.write_text("not for export")
    bundle, crafted = tmp_path / "b.zip", tmp_path / "crafted.zip"
    export_bundle(s, str(bundle))
    with zipfile.ZipFile(bundle) as zin, zipfile.ZipFile(crafted, "w") as zout:
        for n in zin.namelist():
            data = zin.read(n)
            if n == "meta.json":
                m = json.loads(data)
                m.update(source=str(secret), mode="replay")
                data = json.dumps(m).encode()
            zout.writestr(n, data)
    imp = import_bundle(store, str(crafted))
    assert imp.meta()["source"] == "" and imp.meta()["mode"] == "imported"
    assert recording_of(imp) is None
    # even a hand-edited meta.json cannot make a non-pcap file "the recording"
    imp.update_meta(source=str(secret), mode="replay", imported_from=None)
    assert recording_of(imp) is None
