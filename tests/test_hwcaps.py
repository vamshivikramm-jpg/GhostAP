"""PLAN_3.0 O18: sensor capability intelligence, from real `iw phy` output of the project's sensor."""
import os

from ghostap import hwcaps
from ghostap.config import load_config
from ghostap.web import create_app

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "iw_phy_rtl8821au.txt")


def test_parse_real_rtl8821au_output():
    c = hwcaps.parse_iw_phy(open(FIXTURE).read())
    assert "monitor" in c["modes"] and c["software_modes"] == ["monitor"]
    assert c["combinations"] is False and c["antennas_rx"] == 1 and c["sae"]
    assert c["ht"] and c["vht"] and not c["he"] and not c["eht"]
    assert c["ciphers"] == ["WEP40", "WEP104", "TKIP", "CCMP-128", "CMAC"]
    assert c["bands"]["2.4"][:3] == [1, 2, 3] and 36 in c["bands"]["5"] and "6" not in c["bands"]
    assert c["max_scan_ssids"] == 9 and not c["scheduled_scan"]
    what = {x["what"] for x in hwcaps.limits(c)}
    assert "6 GHz networks (Wi-Fi 6E / Wi-Fi 7 on 6 GHz) are not heard" in what
    assert "active checks pause passive capture" in what and "no direction finding" in what
    assert "5 GHz networks are not heard" not in what


def test_disabled_channels_are_not_counted():
    text = "Wiphy phy1\n\tBand 1:\n\t\tFrequencies:\n\t\t\t* 2412.0 MHz [1] (20.0 dBm)\n" \
           "\t\t\t* 2467.0 MHz [12] (disabled)\n\tBand 4:\n\t\tFrequencies:\n\t\t\t* 5955.0 MHz [1] (20.0 dBm)\n"
    c = hwcaps.parse_iw_phy(text)
    assert c["bands"] == {"2.4": [1], "6": [1]}


def test_probe_never_raises_without_iw(monkeypatch):
    monkeypatch.setattr(hwcaps, "_run", lambda args: None)
    r = hwcaps.probe("wlan9")
    assert r["available"] is False and "failed" in r["error"]


def test_endpoint(tmp_path, monkeypatch):
    app = create_app(str(tmp_path / "s.db"), load_config(os.path.join(ROOT, "config.yaml")),
                     admin_db=str(tmp_path / "a.db"), monitored_path=str(tmp_path / "m.json"))
    c = app.test_client()
    r = c.get("/api/sensor/capabilities").get_json()
    assert r["available"] is False and "from a file" in r["reason"]           # no live capture
    ctx = app.extensions["ghostap"]
    monkeypatch.setattr(ctx, "status", lambda: {"mode": "live", "source": "wlan0"})
    monkeypatch.setattr(hwcaps, "probe", lambda iface: {"iface": iface, "available": True, "limits": []})
    hwcaps._cache.clear()
    assert c.get("/api/sensor/capabilities").get_json() == {"iface": "wlan0", "available": True, "limits": []}
