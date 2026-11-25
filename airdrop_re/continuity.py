"""Decoder for Apple Continuity BLE advertisements.

Apple devices put a stream of TLVs (type, length, value) inside BLE
manufacturer data under company ID 0x004C. Field layouts here follow public
research (furiousMAC/continuity, Celosia & Cunche 2020, OpenDrop) and are
things we verify ourselves against captures -- treat anything marked "?" as
a hypothesis.
"""
import hashlib

APPLE_COMPANY_ID = 0x004C

TYPES = {
    0x02: "iBeacon",
    0x03: "AirPrint",
    0x05: "AirDrop",
    0x06: "HomeKit",
    0x07: "ProximityPairing",
    0x08: "HeySiri",
    0x09: "AirPlayTarget",
    0x0A: "AirPlaySource",
    0x0B: "MagicSwitch",
    0x0C: "Handoff",
    0x0D: "TetheringTarget",
    0x0E: "TetheringSource",
    0x0F: "NearbyAction",
    0x10: "NearbyInfo",
    0x12: "FindMy",
}

NEARBY_INFO_ACTIONS = {
    0x0: "activity unknown",
    0x1: "activity reporting disabled",
    0x3: "idle / locked",
    0x5: "audio, screen off",
    0x7: "screen on",
    0x9: "screen on + video",
    0xA: "watch on wrist, unlocked",
    0xB: "recent user interaction",
    0xD: "driving",
    0xE: "phone/FaceTime call",
}

NEARBY_ACTION_TYPES = {
    0x01: "Apple TV setup",
    0x04: "mobile backup",
    0x05: "watch setup",
    0x06: "Apple TV pair",
    0x07: "internet relay",
    0x08: "Wi-Fi password share",
    0x09: "iOS setup",
    0x0A: "repair",
    0x0B: "speaker setup",
    0x0C: "Apple Pay",
    0x0D: "whole-home audio setup",
    0x0E: "dev tools pairing",
    0x0F: "answered call",
    0x10: "ended call",
    0x13: "remote autofill",
    0x14: "companion link proximity",
    0x17: "remote display",
    0x20: "join this TV?",
}

AIRPODS_MODELS = {
    0x0220: "AirPods 1", 0x0F20: "AirPods 2", 0x1320: "AirPods 3",
    0x0E20: "AirPods Pro", 0x1420: "AirPods Pro 2", 0x0A20: "AirPods Max",
    0x0520: "BeatsX", 0x0620: "Beats Solo3", 0x0B20: "Powerbeats Pro",
}


def parse_tlvs(data: bytes):
    """Split Apple manufacturer data into (type, value, truncated) tuples."""
    out, i = [], 0
    while i + 2 <= len(data):
        t, length = data[i], data[i + 1]
        v = data[i + 2:i + 2 + length]
        truncated = len(v) < length
        out.append((t, v, truncated))
        if truncated:
            break
        i += 2 + length
    return out


def _hex(b: bytes) -> str:
    return b.hex()


def decode_airdrop(v: bytes, known_hashes=None):
    # 8 zero bytes | version | appleID[2] | phone[2] | email[2] | email2[2] | 0
    if len(v) < 17:
        return {"raw": _hex(v)}
    fields = {
        "version": v[8],
        "appleid": v[9:11],
        "phone": v[11:13],
        "email": v[13:15],
        "email2": v[15:17],
    }
    out = {"version": fields["version"]}
    for k in ("appleid", "phone", "email", "email2"):
        h = fields[k].hex()
        match = (known_hashes or {}).get(h)
        out[k] = f"{h} (= {match})" if match else h
    return out


def decode_nearby_info(v: bytes):
    if len(v) < 2:
        return {"raw": _hex(v)}
    action = v[0] & 0x0F
    return {
        "status_flags?": f"{v[0] >> 4:04b}",
        "action": f"{action:#x} {NEARBY_INFO_ACTIONS.get(action, '?')}",
        "data_flags?": f"{v[1]:08b}",
        "auth_tag": _hex(v[2:]),
    }


def decode_handoff(v: bytes):
    # clipboard | IV/seq[2] | auth tag | encrypted activity (iCloud-keyed)
    if len(v) < 4:
        return {"raw": _hex(v)}
    return {
        "clipboard?": f"{v[0]:#04x}",
        # observed: d21d, d31d, d41d... -> little-endian counter (0x1dd2, 0x1dd3, ...)
        "seq": int.from_bytes(v[1:3], "little"),
        "auth_tag?": f"{v[3]:#04x}",
        "encrypted": _hex(v[4:]),
    }


def decode_nearby_action(v: bytes):
    if len(v) < 2:
        return {"raw": _hex(v)}
    return {
        "flags": f"{v[0]:08b}",
        "type": f"{v[1]:#04x} {NEARBY_ACTION_TYPES.get(v[1], '?')}",
        "data": _hex(v[2:]),
    }


def decode_proximity_pairing(v: bytes):
    if len(v) < 3:
        return {"raw": _hex(v)}
    model = int.from_bytes(v[1:3], "little")
    return {
        "model": f"{model:#06x} {AIRPODS_MODELS.get(model, '?')}",
        "rest": _hex(v[3:]),
    }


def decode_airplay_target(v: bytes):
    # observed layout: flags | seed? | IPv4 (4 bytes) | port (2 bytes, 7000 = AirPlay)
    if len(v) < 8:
        return {"raw": _hex(v)}
    ip = ".".join(str(b) for b in v[2:6])
    return {"flags?": f"{v[0]:#04x}", "seed?": f"{v[1]:#04x}",
            "ip": ip, "port": int.from_bytes(v[6:8], "big")}


DECODERS = {
    0x09: decode_airplay_target,
    0x05: decode_airdrop,
    0x0C: decode_handoff,
    0x0F: decode_nearby_action,
    0x10: decode_nearby_info,
    0x07: decode_proximity_pairing,
}


def decode(data: bytes, known_hashes=None):
    """Decode a full Apple manufacturer-data blob into a list of messages."""
    msgs = []
    for t, v, truncated in parse_tlvs(data):
        name = TYPES.get(t, f"unknown{t:#04x}")
        dec = DECODERS.get(t)
        if dec is decode_airdrop:
            fields = dec(v, known_hashes)
        elif dec:
            fields = dec(v)
        else:
            fields = {"raw": _hex(v)}
        if truncated:
            fields["truncated"] = True
        msgs.append((name, fields))
    return msgs


def identity_hashes(phones=(), emails=()):
    """First 2 bytes of SHA-256 for several plausible formats of each identifier.

    We don't yet know exactly how Apple normalizes these before hashing, so
    we try variants and see which one matches the beacon. Finding out is
    part of the research.
    """
    table = {}
    for p in phones:
        digits = "".join(c for c in p if c.isdigit())
        for variant in {p, digits, "+" + digits, digits[-10:]}:
            table[hashlib.sha256(variant.encode()).digest()[:2].hex()] = f"phone '{variant}'"
    for e in emails:
        for variant in {e, e.lower(), e.strip().lower()}:
            table[hashlib.sha256(variant.encode()).digest()[:2].hex()] = f"email '{variant}'"
    return table
