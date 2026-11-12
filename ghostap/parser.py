"""Turn a captured 802.11 management frame into a flat observation dict.

Only beacon and probe-response frames are handled; everything else is ignored.
"""
from __future__ import annotations

import hashlib
from typing import Any, Optional

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, RadioTap

HIDDEN_SSID = "<hidden>"

# Strongest first. Scapy's crypto entries look like "WPA2/PSK", "WPA3/SAE", "OPN", "WEP".
_SECURITY_RANK = ("WPA3", "WPA2", "WPA", "WEP", "OPN")


def security_rank(entry: str) -> int:
    """0 = strongest (WPA3) ... 4 = OPN; unknown families sort last."""
    family = entry.split("/", 1)[0].upper()
    try:
        return _SECURITY_RANK.index(family)
    except ValueError:
        return len(_SECURITY_RANK)


def strongest_security(crypto: Optional[set]) -> str:
    """Pick the strongest entry of Scapy's crypto set (WPA3 > WPA2 > WPA > WEP > OPN)."""
    if not crypto:
        return "OPN"
    return sorted(crypto, key=lambda e: (security_rank(e), e))[0]


def _clean_ssid(ssid: Any) -> str:
    if isinstance(ssid, bytes):
        ssid = ssid.decode("utf-8", errors="replace")
    if ssid is None:
        return HIDDEN_SSID
    ssid = str(ssid)
    # Hidden networks send an empty SSID or a run of NUL bytes.
    if not ssid.strip("\x00").strip():
        return HIDDEN_SSID
    return ssid


def _rssi(pkt) -> Optional[int]:
    if not pkt.haslayer(RadioTap):
        return None
    val = getattr(pkt[RadioTap], "dBm_AntSignal", None)
    return int(val) if val is not None else None


# Information elements whose *contents* identify the AP hardware / software.
_FP_CONTENT_IDS = {1, 50, 127}          # supported rates, extended rates, extended capabilities
_FP_PREFIX_IDS = {45: 3, 191: 4}        # HT capabilities (info + A-MPDU), VHT capabilities info
_FP_SKIP_IDS = {48}                     # RSN: security is its own indicator
_WPA_IE = b"\x00\x50\xf2\x01"           # Microsoft WPA vendor element (also security)
# Capability bits that change at run time or with the security setting:
# privacy (0x0010), short preamble (0x0020), short slot time (0x0400).
_CAP_MASK = 0xFFFF & ~(0x0010 | 0x0020 | 0x0400)


def beacon_fingerprint(body) -> Optional[str]:
    """Hash of how a beacon is *built*, not what network it advertises.

    Different AP models and AP software (vendor firmware, hostapd, phone hotspots)
    order and fill their information elements differently, so a twin running on
    other hardware usually has a different fingerprint from the real APs, even
    when it copies the SSID, vendor OUI, channel and security.
    """
    try:
        v = int(body.cap)
        cap = ((v & 0xFF) << 8) | (v >> 8)   # Scapy's value is byte-swapped vs. IEEE 802.11
        parts = ["cap={:04x}".format(cap & _CAP_MASK)]
        elt = body.payload
        while isinstance(elt, Dot11Elt):
            eid = int(elt.ID)
            raw = bytes(elt)[2:2 + int(elt.len or 0)]
            if eid in _FP_SKIP_IDS or (eid == 221 and raw[:4] == _WPA_IE):
                pass
            elif eid in _FP_CONTENT_IDS:
                parts.append("{}:{}".format(eid, raw.hex()))
            elif eid in _FP_PREFIX_IDS:
                parts.append("{}:{}".format(eid, raw[:_FP_PREFIX_IDS[eid]].hex()))
            elif eid == 221:
                parts.append("221:{}".format(raw[:4].hex()))   # vendor OUI + type
            else:
                parts.append(str(eid))                         # presence and order only
            elt = elt.payload
        return hashlib.sha1("|".join(parts).encode()).hexdigest()[:12]
    except Exception:  # malformed elements: no fingerprint rather than a crash
        return None


def parse_frame(pkt) -> Optional[dict]:
    """Return an observation dict for a beacon / probe response, else None."""
    if pkt.haslayer(Dot11Beacon):
        body = pkt[Dot11Beacon]
        frame_type = "beacon"
    elif pkt.haslayer(Dot11ProbeResp):
        body = pkt[Dot11ProbeResp]
        frame_type = "probe_resp"
    else:
        return None

    dot11 = pkt[Dot11]
    bssid = (dot11.addr3 or dot11.addr2 or "").lower()
    if not bssid:
        return None

    try:
        stats = body.network_stats()
    except Exception:  # malformed information elements
        stats = {}

    channel = stats.get("channel")
    sc = dot11.SC

    return {
        "ts": float(pkt.time),
        "frame_type": frame_type,
        "ssid": _clean_ssid(stats.get("ssid")),
        "bssid": bssid,
        "oui": bssid[:8],
        "channel": int(channel) if channel is not None else None,
        "security": strongest_security(stats.get("crypto")),
        "rssi": _rssi(pkt),
        "beacon_interval": int(body.beacon_interval) if body.beacon_interval is not None else None,
        "tsf": int(body.timestamp) if body.timestamp is not None else None,
        "seq": (int(sc) >> 4) if sc is not None else None,
        "fingerprint": beacon_fingerprint(body),
    }
