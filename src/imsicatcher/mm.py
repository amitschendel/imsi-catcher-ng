"""Mobility Management messages (3GPP TS 24.008 section 9.2)."""

from __future__ import annotations

from datetime import datetime, timezone

from . import ie
from .ie import IEError

MSG_NAMES = {
    0x01: "IMSI Detach Indication",
    0x02: "Location Updating Accept",
    0x04: "Location Updating Reject",
    0x08: "Location Updating Request",
    0x11: "Authentication Reject",
    0x12: "Authentication Request",
    0x14: "Authentication Response",
    0x1C: "Authentication Failure",
    0x18: "Identity Request",
    0x19: "Identity Response",
    0x1A: "TMSI Reallocation Command",
    0x1B: "TMSI Reallocation Complete",
    0x21: "CM Service Accept",
    0x22: "CM Service Reject",
    0x23: "CM Service Abort",
    0x24: "CM Service Request",
    0x25: "CM Service Prompt",
    0x28: "CM Re-establishment Request",
    0x29: "Abort",
    0x30: "MM Null",
    0x31: "MM Status",
    0x32: "MM Information",
}

LU_TYPES = ("normal", "periodic", "IMSI attach", "reserved")
CM_SERVICE_TYPES = {
    1: "mobile originating call / packet mode",
    2: "emergency call",
    4: "SMS",
    8: "supplementary services",
    9: "voice group call",
    10: "voice broadcast call",
    11: "location services",
}
IDENTITY_TYPES = {1: "IMSI", 2: "IMEI", 3: "IMEISV", 4: "TMSI", 5: "P-TMSI/RAI/P-TMSI signature"}
REJECT_CAUSES = {
    2: "IMSI unknown in HLR",
    3: "illegal MS",
    4: "IMSI unknown in VLR",
    5: "IMEI not accepted",
    6: "illegal ME",
    11: "PLMN not allowed",
    12: "location area not allowed",
    13: "roaming not allowed in this location area",
    15: "no suitable cells in location area",
    17: "network failure",
    20: "MAC failure",
    21: "synch failure",
    22: "congestion",
    23: "GSM authentication unacceptable",
    25: "not authorized for this CSG",
    32: "service option not supported",
    33: "requested service option not subscribed",
    34: "service option temporarily out of order",
    38: "call cannot be identified",
    95: "semantically incorrect message",
    96: "invalid mandatory information",
    97: "message type non-existent or not implemented",
    98: "message type not compatible with protocol state",
    99: "information element non-existent or not implemented",
    100: "conditional IE error",
    101: "message not compatible with protocol state",
    111: "protocol error, unspecified",
}

# GSM 03.38 default alphabet (basic table) for network names.
_GSM7 = (
    "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?"
    "¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"
)


def _cause(code: int) -> str:
    if 48 <= code <= 63:
        return "retry upon entry into a new cell"
    return REJECT_CAUSES.get(code, f"cause {code}")


def _lv_identity(body: bytes, off: int) -> tuple[dict, int]:
    n = body[off]
    v = body[off + 1:off + 1 + n]
    if len(v) != n:
        raise IEError("identity truncated")
    return ie.mobile_identity(v), off + 1 + n


# 23.038 6.2.1.1 extension table, reached through the ESC septet.
_GSM7_EXT = {0x0A: "\f", 0x14: "^", 0x28: "{", 0x29: "}", 0x2F: "\\", 0x3C: "[", 0x3D: "~",
             0x3E: "]", 0x40: "|", 0x65: "\u20ac"}


def gsm7_unpack(data: bytes, spare_bits: int = 0) -> str:
    n_chars = (len(data) * 8 - spare_bits) // 7
    out = []
    escape = False
    for i in range(n_chars):
        bit = i * 7
        byte, shift = divmod(bit, 8)
        v = data[byte] >> shift
        if shift > 1 and byte + 1 < len(data):
            v |= data[byte + 1] << (8 - shift)
        v &= 0x7F
        if escape:
            out.append(_GSM7_EXT.get(v, " "))
            escape = False
        elif v == 0x1B:
            escape = True
        else:
            out.append(_GSM7[v])
    return "".join(out)


def network_name(v: bytes) -> str | None:
    if not v:
        return None
    coding = (v[0] >> 4) & 0x07
    spare = v[0] & 0x07
    if coding == 0:
        return gsm7_unpack(v[1:], spare)
    if coding == 1:
        return v[1:].decode("utf-16-be", errors="replace")
    return None


def _swapped_bcd(b: int) -> int:
    return (b & 0x0F) * 10 + (b >> 4)


def _tz_quarters(b: int) -> int:
    q = (b & 0x07) * 10 + (b >> 4)
    return -q if b & 0x08 else q


def location_updating_request(body: bytes) -> dict:
    lu = body[2]
    out = {
        "lu_type": LU_TYPES[lu & 0x03],
        "follow_on_request": bool(lu & 0x08),
        "cksn": (lu >> 4) & 0x07,
        "old_lai": ie.lai(body[3:8]),
    }
    out["identity"], _ = _lv_identity(body, 9)
    return out


def cm_service_request(body: bytes) -> dict:
    b = body[2]
    out = {"service": CM_SERVICE_TYPES.get(b & 0x0F, f"type {b & 0x0F}"), "cksn": (b >> 4) & 0x07}
    off = 4 + body[3]  # skip MS classmark 2
    out["identity"], _ = _lv_identity(body, off)
    return out


def cm_reestablishment_request(body: bytes) -> dict:
    off = 4 + body[3]
    ident, off = _lv_identity(body, off)
    out = {"cksn": body[2] & 0x07, "identity": ident}
    if off + 6 <= len(body) and body[off] == 0x13:
        out["lai"] = ie.lai(body[off + 1:off + 6])
    return out


def imsi_detach(body: bytes) -> dict:
    out = {}
    out["identity"], _ = _lv_identity(body, 3)  # after MS classmark 1
    return out


def identity_request(body: bytes) -> dict:
    t = body[2] & 0x07
    return {"identity_type": IDENTITY_TYPES.get(t, f"type {t}")}


def identity_response(body: bytes) -> dict:
    out = {}
    out["identity"], _ = _lv_identity(body, 2)
    return out


def location_updating_accept(body: bytes) -> dict:
    out = {"lai": ie.lai(body[2:7])}
    off = 7
    while off < len(body):
        iei = body[off]
        if iei == 0x17:
            out["identity"], off = _lv_identity(body, off + 1)
        elif iei == 0xA1:
            out["follow_on_proceed"] = True
            off += 1
        elif iei == 0xA2:
            out["cts_permission"] = True
            off += 1
        elif iei in (0x4A, 0x34, 0x35):  # TLV: equivalent PLMNs, emergency numbers, per-MS T3212
            if off + 1 >= len(body):
                break
            off += 2 + body[off + 1]
        else:
            break
    return out


def location_updating_reject(body: bytes) -> dict:
    return {"cause_code": body[2], "cause": _cause(body[2])}


def cm_service_reject(body: bytes) -> dict:
    return location_updating_reject(body)


def tmsi_reallocation_command(body: bytes) -> dict:
    out = {"lai": ie.lai(body[2:7])}
    out["identity"], _ = _lv_identity(body, 7)
    return out


def authentication_request(body: bytes) -> dict:
    # RAND is not kept; only whether the challenge is 2G (GSM) or 3G (UMTS AKA) style.
    off = 3 + 16
    if len(body) < off:
        raise IEError("authentication request truncated")
    return {"cksn": body[2] & 0x07, "umts_aka": off < len(body) and body[off] == 0x20}


def mm_information(body: bytes) -> dict:
    out: dict = {}
    off = 2
    while off < len(body):
        iei = body[off]
        if iei in (0x43, 0x45, 0x48, 0x49):
            if off + 1 >= len(body):
                break
            n = body[off + 1]
            v = body[off + 2:off + 2 + n]
            if iei == 0x43:
                out["network_full_name"] = network_name(v)
            elif iei == 0x45:
                out["network_short_name"] = network_name(v)
            elif iei == 0x49 and v:
                out["daylight_saving_hours"] = v[0] & 0x03
            off += 2 + n
        elif iei == 0x46:
            out["utc_offset_minutes"] = _tz_quarters(body[off + 1]) * 15
            off += 2
        elif iei == 0x47:
            v = body[off + 1:off + 8]
            if len(v) == 7:
                try:
                    t = datetime(
                        2000 + _swapped_bcd(v[0]), _swapped_bcd(v[1]), _swapped_bcd(v[2]),
                        _swapped_bcd(v[3]), _swapped_bcd(v[4]), _swapped_bcd(v[5]),
                        tzinfo=timezone.utc,
                    )
                    out["network_time_utc"] = t.isoformat()
                except ValueError:
                    pass
                out["utc_offset_minutes"] = _tz_quarters(v[6]) * 15
            off += 8
        else:
            break
    return out


HANDLERS = {
    0x08: location_updating_request,
    0x24: cm_service_request,
    0x28: cm_reestablishment_request,
    0x01: imsi_detach,
    0x18: identity_request,
    0x19: identity_response,
    0x02: location_updating_accept,
    0x04: location_updating_reject,
    0x22: cm_service_reject,
    0x1A: tmsi_reallocation_command,
    0x12: authentication_request,
    0x32: mm_information,
}


def decode(body: bytes) -> dict:
    """Decode an MM message; `body` starts at the protocol discriminator octet."""
    # Bits 8..7 carry the send sequence number N(SD) on uplink messages.
    mt = body[1] & 0x3F
    msg = {"pd": "MM", "mt": mt, "name": MSG_NAMES.get(mt, f"MM 0x{mt:02x}")}
    handler = HANDLERS.get(mt)
    if handler is not None:
        try:
            msg.update(handler(body))
        except (IEError, IndexError) as e:
            msg["error"] = str(e) or type(e).__name__
    return msg

