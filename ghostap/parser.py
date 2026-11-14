"""Turn a captured 802.11 management frame into a flat observation dict.

Beacons and probe responses become observations (parse_frame). Deauthentication and
disassociation frames become attack-activity events (parse_event); for those only the
AP address, broadcast/unicast and the reason code are kept, never client addresses.
Everything else is ignored.
"""
from __future__ import annotations

import hashlib
from typing import Any, List, Optional

from scapy.layers.dot11 import (
    Dot11, Dot11Beacon, Dot11Deauth, Dot11Disas, Dot11Elt, Dot11ProbeResp, RadioTap,
)

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
    """Hash of how a beacon is *built*, not what network it advertises (see beacon_layout)."""
    return fingerprint_of(beacon_layout(body))


def fingerprint_of(layout: Optional[List[str]]) -> Optional[str]:
    if layout is None:
        return None
    return hashlib.sha1("|".join(layout).encode(), usedforsecurity=False).hexdigest()[:12]


def beacon_layout(body) -> Optional[List[str]]:
    """How a beacon is *built*: the parts its fingerprint hashes (F028 shows them).

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
            elif eid == 255 and raw:
                # extension elements (Wi-Fi 6/6E): which ones, plus HE MAC capabilities
                parts.append("255:{:02x}{}".format(
                    raw[0], ":" + raw[1:7].hex() if raw[0] == 35 else ""))
            else:
                parts.append(str(eid))                         # presence and order only
            elt = elt.payload
        return parts
    except Exception:  # malformed elements: no fingerprint rather than a crash
        return None


REJECT_REASONS = ("not_beacon", "bad_fcs", "truncated", "malformed")

# ---- RSN (security) details: F004 ------------------------------------------- #
_CIPHERS = {1: "WEP40", 2: "TKIP", 4: "CCMP", 5: "WEP104", 8: "GCMP", 9: "GCMP-256", 10: "CCMP-256"}
_AKMS = {1: "802.1X", 2: "PSK", 3: "FT-802.1X", 4: "FT-PSK", 5: "802.1X-SHA256", 6: "PSK-SHA256",
         8: "SAE", 9: "FT-SAE", 11: "802.1X-B", 12: "802.1X-B192", 18: "OWE", 24: "SAE-EXT", 25: "FT-SAE-EXT"}
CIPHER_RANK = {"WEP40": 0, "WEP104": 0, "TKIP": 1, "CCMP": 2, "GCMP": 2, "CCMP-256": 3, "GCMP-256": 3}
_MGMT_CIPHERS = {6: "BIP-CMAC-128", 11: "BIP-GMAC-128", 12: "BIP-GMAC-256", 13: "BIP-CMAC-256"}


def akm_class(akm: str) -> float:
    """3 = enterprise (802.1X), 2 = WPA3 personal (SAE), 1 = password (PSK),
    0.5 = OWE (encrypted but without any password or login: anyone can run one under any
    name, so it proves nothing about who runs the network), 0 = unknown."""
    if "802.1X" in akm:
        return 3
    if akm.startswith(("SAE", "FT-SAE")):
        return 2
    if "PSK" in akm:
        return 1
    if akm.startswith("OWE"):
        return 0.5
    return 0


def parse_rsn(body) -> Optional[str]:
    """Compact RSN summary, e.g. 'pw=CCMP;akm=PSK,SAE;pmf=capable;grp=CCMP;gmgmt=BIP-CMAC-128',
    or None without RSN. grp = group (broadcast) cipher, gmgmt = group management cipher
    (only present when the AP sends it, usually with PMF)."""
    elt = body.payload
    while isinstance(elt, Dot11Elt):
        if int(elt.ID) == 48:
            raw = bytes(elt)[2:2 + int(elt.len or 0)]
            break
        elt = elt.payload
    else:
        return None
    try:
        grp = _CIPHERS.get(raw[5], "?{}".format(raw[5])) if len(raw) >= 6 else None
        i = 2 + 4                                   # version, group cipher
        n = int.from_bytes(raw[i:i + 2], "little")
        i += 2
        pw = [_CIPHERS.get(raw[i + 4 * k + 3], "?{}".format(raw[i + 4 * k + 3])) for k in range(n)]
        i += 4 * n
        n = int.from_bytes(raw[i:i + 2], "little")
        i += 2
        akm = [_AKMS.get(raw[i + 4 * k + 3], "?{}".format(raw[i + 4 * k + 3])) for k in range(n)]
        i += 4 * n
        caps = int.from_bytes(raw[i:i + 2], "little") if len(raw) >= i + 2 else 0
        pmf = "required" if caps & 0x40 else "capable" if caps & 0x80 else "none"
        out = "pw={};akm={};pmf={}".format(",".join(pw), ",".join(akm), pmf)
        if grp:
            out += ";grp=" + grp
        i += 2
        if len(raw) >= i + 2:                       # PMKID list, then group management cipher
            n = int.from_bytes(raw[i:i + 2], "little")
            i += 2 + 16 * n
            if len(raw) >= i + 4:
                out += ";gmgmt=" + _MGMT_CIPHERS.get(raw[i + 3], "?{}".format(raw[i + 3]))
        return out
    except (IndexError, ValueError):
        return None


def rsn_fields(rsn: Optional[str]) -> dict:
    """'pw=CCMP;akm=PSK;pmf=none' -> {'pw': [...], 'akm': [...], 'pmf': 'none'}"""
    out = {"pw": [], "akm": [], "pmf": None, "grp": None, "gmgmt": None}
    for part in (rsn or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k] = v if k in ("pmf", "grp", "gmgmt") else [x for x in v.split(",") if x]
    return out


# ---- frequency / band: F009 -------------------------------------------------- #

def _freq(pkt) -> Optional[int]:
    if not pkt.haslayer(RadioTap):
        return None
    f = getattr(pkt[RadioTap], "ChannelFrequency", None)
    return int(f) if f else None


def band_of(freq: Optional[int]) -> Optional[str]:
    if not freq:
        return None
    if 2400 <= freq <= 2500:
        return "2.4"
    if 5925 <= freq <= 7125:
        return "6"
    if 4900 <= freq < 5925:
        return "5"
    return None


def channel_from_freq(freq: Optional[int]) -> Optional[int]:
    b = band_of(freq)
    if b == "2.4":
        return 14 if freq == 2484 else (freq - 2407) // 5
    if b == "5":
        return (freq - 5000) // 5
    if b == "6":
        return (freq - 5950) // 5
    return None


def _bad_fcs(pkt) -> bool:
    """The driver says the frame failed its checksum (radio corruption)."""
    if not pkt.haslayer(RadioTap):
        return False
    flags = getattr(pkt[RadioTap], "Flags", None)
    return flags is not None and "badFCS" in str(flags)


def _truncated(pkt, body) -> bool:
    """Frame cut short (capture snap length) or an element longer than the data left."""
    wirelen = getattr(pkt, "wirelen", None)
    if wirelen and len(bytes(pkt)) < wirelen:
        return True
    elt = body.payload
    while isinstance(elt, Dot11Elt):
        if elt.len is not None and len(bytes(elt)) < 2 + int(elt.len):
            return True
        elt = elt.payload
    return False


def _has_ssid_element(body) -> bool:
    elt = body.payload
    while isinstance(elt, Dot11Elt):
        if int(elt.ID) == 0:
            return True
        elt = elt.payload
    return False


def parse_frame(pkt, stats: Optional[dict] = None) -> Optional[dict]:
    """Return an observation dict for a beacon / probe response, else None.

    Frames that are corrupted (bad FCS), truncated or malformed are rejected
    instead of being guessed at: a damaged beacon can carry a garbage SSID or
    BSSID, or lose its security element and look like an open network, which
    would create false alarms. Pass a dict as `stats` to count rejections by
    reason (see REJECT_REASONS).
    """
    def reject(reason):
        if stats is not None:
            stats[reason] = stats.get(reason, 0) + 1
        return None

    try:
        if pkt.haslayer(Dot11Beacon):
            body = pkt[Dot11Beacon]
            frame_type = "beacon"
        elif pkt.haslayer(Dot11ProbeResp):
            body = pkt[Dot11ProbeResp]
            frame_type = "probe_resp"
        else:
            return reject("not_beacon")
        if _bad_fcs(pkt):
            return reject("bad_fcs")
        if _truncated(pkt, body):
            return reject("truncated")
        if not _has_ssid_element(body):          # mandatory in every beacon / probe response
            return reject("malformed")

        dot11 = pkt[Dot11]
        bssid = (dot11.addr3 or dot11.addr2 or "").lower()
        if not bssid:
            return reject("malformed")
        info = body.network_stats()
        freq = _freq(pkt)
        channel = info.get("channel")
        if channel is None or band_of(freq) == "6":     # 6 GHz numbers overlap 2.4 GHz ones
            channel = channel_from_freq(freq) if freq else channel
        sc = dot11.SC
        layout = beacon_layout(body)
        return {
            "ts": float(pkt.time),
            "frame_type": frame_type,
            "ssid": _clean_ssid(info.get("ssid")),
            "bssid": bssid,
            "oui": bssid[:8],
            "channel": int(channel) if channel is not None else None,
            "security": strongest_security(info.get("crypto")),
            "rssi": _rssi(pkt),
            "beacon_interval": int(body.beacon_interval) if body.beacon_interval is not None else None,
            "tsf": int(body.timestamp) if body.timestamp is not None else None,
            "seq": (int(sc) >> 4) if sc is not None else None,
            "fingerprint": fingerprint_of(layout),
            "rsn": parse_rsn(body),
            "freq": freq,
            "layout": layout,          # not a column: stored once per fingerprint (F028)
        }
    except Exception:  # anything Scapy cannot make sense of: untrusted radio input
        return reject("malformed")


def parse_event(pkt, stats: Optional[dict] = None) -> Optional[dict]:
    """Deauthentication / disassociation frame -> attack-activity event (F005), else None.

    Privacy: only the AP address (BSSID) is kept, plus whether the frame was sent to
    everyone (broadcast) and its reason code. Client addresses are never stored.
    """
    try:
        if pkt.haslayer(Dot11Deauth):
            kind, body = "deauth", pkt[Dot11Deauth]
        elif pkt.haslayer(Dot11Disas):
            kind, body = "disassoc", pkt[Dot11Disas]
        else:
            return None
        if _bad_fcs(pkt):
            if stats is not None:
                stats["bad_fcs"] = stats.get("bad_fcs", 0) + 1
            return None
        d = pkt[Dot11]
        bssid = (d.addr3 or "").lower()
        if not bssid or bssid == "ff:ff:ff:ff:ff:ff":
            return None
        return {"ts": float(pkt.time), "kind": kind, "bssid": bssid,
                "broadcast": (d.addr1 or "").lower() == "ff:ff:ff:ff:ff:ff",
                "reason": int(body.reason) if body.reason is not None else None,
                "rssi": _rssi(pkt), "freq": _freq(pkt)}
    except Exception:
        if stats is not None:
            stats["malformed"] = stats.get("malformed", 0) + 1
        return None
