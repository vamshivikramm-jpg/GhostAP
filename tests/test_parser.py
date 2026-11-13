from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap

from ghostap.parser import HIDDEN_SSID, parse_frame, strongest_security

RSN_WPA2_PSK = bytes.fromhex("0100000fac040100000fac040100000fac020000")


def beacon(ssid, bssid, channel, wpa2, rssi=-60, seq=42, tsf=123456789):
    pkt = (
        RadioTap(present="dBm_AntSignal", dBm_AntSignal=rssi)
        / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                addr2=bssid, addr3=bssid, SC=seq << 4)
        / Dot11Beacon(beacon_interval=100, timestamp=tsf,
                      cap="ESS+privacy" if wpa2 else "ESS")
        / Dot11Elt(ID="SSID", info=ssid.encode())
        / Dot11Elt(ID="DSset", info=bytes([channel]))
    )
    if wpa2:
        pkt = pkt / Dot11Elt(ID=48, info=RSN_WPA2_PSK)
    pkt = RadioTap(bytes(pkt))  # round-trip through raw bytes like a real capture
    pkt.time = 1700000000.5
    return pkt


def test_wpa2_beacon():
    obs = parse_frame(beacon("MVSR_WiFi", "A4:2B:B0:11:22:33", 6, True, rssi=-55))
    fp = obs.pop("fingerprint")
    assert isinstance(fp, str) and len(fp) == 12
    assert obs.pop("rsn") == "pw=CCMP;akm=PSK;pmf=none"
    assert obs.pop("freq") is None                 # this test frame has no frequency field
    assert obs == {
        "ts": 1700000000.5,
        "frame_type": "beacon",
        "ssid": "MVSR_WiFi",
        "bssid": "a4:2b:b0:11:22:33",
        "oui": "a4:2b:b0",
        "channel": 6,
        "security": "WPA2/PSK",
        "rssi": -55,
        "beacon_interval": 100,
        "tsf": 123456789,
        "seq": 42,
    }


def test_open_beacon():
    obs = parse_frame(beacon("Cafe_Guest", "f0:9f:c2:aa:bb:cc", 11, False, rssi=-75))
    assert obs["security"] == "OPN"
    assert obs["channel"] == 11
    assert obs["ssid"] == "Cafe_Guest"
    assert obs["rssi"] == -75


def test_hidden_ssid():
    obs = parse_frame(beacon("", "f0:9f:c2:aa:bb:cc", 1, False))
    assert obs["ssid"] == HIDDEN_SSID


def test_data_frame_returns_none():
    pkt = RadioTap() / Dot11(type=2, subtype=0, addr1="ff:ff:ff:ff:ff:ff",
                             addr2="a4:2b:b0:11:22:33", addr3="a4:2b:b0:11:22:33")
    assert parse_frame(pkt) is None


def test_strongest_security_order():
    assert strongest_security({"OPN"}) == "OPN"
    assert strongest_security({"WPA/PSK", "WPA2/PSK"}) == "WPA2/PSK"
    assert strongest_security({"WPA2/PSK", "WPA3/SAE"}) == "WPA3/SAE"
    assert strongest_security({"WEP"}) == "WEP"
    assert strongest_security(set()) == "OPN"


def test_fingerprint_ignores_ssid_channel_and_security():
    a = parse_frame(beacon("MVSR_WiFi", "a4:2b:b0:11:22:33", 6, True))
    b = parse_frame(beacon("Other", "00:c0:ca:de:ad:01", 11, False))
    assert a["fingerprint"] == b["fingerprint"]


def test_fingerprint_differs_for_other_ap_software():
    import os
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
    from make_test_pcap import make_beacon
    fps = {}
    for profile in ("enterprise", "soho", "hostapd", "phone"):
        pkt = RadioTap(bytes(make_beacon("Net", "a4:2b:b0:11:22:33", 6, True, -50, 1000, 1,
                                         profile=profile)))
        pkt.time = 1.0
        fps[profile] = parse_frame(pkt)["fingerprint"]
    assert len(set(fps.values())) == 4, fps
    # the same profile with and without WPA2 must match (security has its own indicator)
    open_pkt = RadioTap(bytes(make_beacon("Net", "a4:2b:b0:11:22:33", 1, False, -50, 1000, 1,
                                          profile="enterprise")))
    open_pkt.time = 1.0
    assert parse_frame(open_pkt)["fingerprint"] == fps["enterprise"]
