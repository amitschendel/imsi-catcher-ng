"""Information elements shared by RR and MM (3GPP TS 24.008 / 44.018)."""

from __future__ import annotations

from .bits import BitReader, BitsExhausted

ID_NONE = "none"
ID_IMSI = "imsi"
ID_IMEI = "imei"
ID_IMEISV = "imeisv"
ID_TMSI = "tmsi"
ID_TMGI = "tmgi"

_ID_TYPES = {0: ID_NONE, 1: ID_IMSI, 2: ID_IMEI, 3: ID_IMEISV, 4: ID_TMSI, 5: ID_TMGI}


class IEError(ValueError):
    pass


def bcd_digits(data: bytes, first_high_only: bool = False) -> str:
    """Decode TBCD digits, low nibble first. Stops at the 0xF filler."""
    out = []
    for i, b in enumerate(data):
        lo, hi = b & 0x0F, b >> 4
        if not (first_high_only and i == 0):
            if lo == 0x0F:
                break
            out.append(lo)
        if hi == 0x0F:
            break
        out.append(hi)
    if any(d > 9 for d in out):
        raise IEError("non-decimal BCD digit")
    return "".join(map(str, out))


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def mobile_identity(v: bytes) -> dict:
    """Decode a Mobile Identity value part (24.008 10.5.1.4).

    Returns {"kind": ..., "value": ...}; TMSI values are 8 upper-case hex digits.
    """
    if not v:
        raise IEError("empty mobile identity")
    b0 = v[0]
    kind = _ID_TYPES.get(b0 & 0x07)
    if kind is None:
        raise IEError(f"unknown identity type {b0 & 0x07}")
    if kind == ID_NONE:
        return {"kind": ID_NONE, "value": None}
    if kind == ID_TMSI:
        if len(v) != 5:
            raise IEError("TMSI identity must be 5 octets")
        return {"kind": ID_TMSI, "value": v[1:5].hex().upper()}
    if kind == ID_TMGI:
        return {"kind": ID_TMGI, "value": v[1:].hex().upper()}
    odd = bool(b0 & 0x08)
    digits = [b0 >> 4]
    for b in v[1:]:
        digits.append(b & 0x0F)
        digits.append(b >> 4)
    if not odd:
        if digits[-1] != 0x0F:
            raise IEError("even identity without filler")
        digits.pop()
    if any(d > 9 for d in digits):
        raise IEError("non-decimal identity digit")
    value = "".join(map(str, digits))
    if kind == ID_IMSI and not 6 <= len(value) <= 15:
        raise IEError(f"IMSI length {len(value)} out of range")
    if kind == ID_IMEI and len(value) != 15:
        raise IEError("IMEI must have 15 digits")
    if kind == ID_IMEISV and len(value) != 16:
        raise IEError("IMEISV must have 16 digits")
    out = {"kind": kind, "value": value}
    if kind == ID_IMEI:
        out["luhn_ok"] = luhn_ok(value)
    return out


def plmn(v: bytes) -> tuple[str, str]:
    """Decode a 3-octet PLMN identity into (mcc, mnc) strings."""
    if len(v) < 3:
        raise IEError("short PLMN")
    d = (v[0] & 0x0F, v[0] >> 4, v[1] & 0x0F)
    if any(x > 9 for x in d):
        raise IEError("bad MCC digit")
    mcc = f"{d[0]}{d[1]}{d[2]}"
    m1, m2, m3 = v[2] & 0x0F, v[2] >> 4, v[1] >> 4
    if m1 > 9 or m2 > 9 or (m3 != 0x0F and m3 > 9):
        raise IEError("bad MNC digit")
    mnc = f"{m1}{m2}" if m3 == 0x0F else f"{m1}{m2}{m3}"
    return mcc, mnc


def lai(v: bytes) -> dict:
    """Location Area Identification (5 octets)."""
    if len(v) < 5:
        raise IEError("short LAI")
    if v[0] == 0xFF and v[1] == 0xFF and v[2] == 0xFF:
        # "Deleted" LAI: the SIM holds no valid location area (24.008 10.5.1.3).
        return {"mcc": None, "mnc": None, "lac": (v[3] << 8) | v[4], "deleted": True}
    mcc, mnc = plmn(v)
    return {"mcc": mcc, "mnc": mnc, "lac": (v[3] << 8) | v[4]}


# 44.018 10.5.2.5 channel type and TDMA offset
def _chan_type(v: int) -> tuple[str, int | None]:
    if v == 0b00001:
        return "TCH/F", None
    if v >> 1 == 0b0001:
        return "TCH/H", v & 0x01
    if v >> 2 == 0b001:
        return "SDCCH/4", v & 0x03
    if v >> 3 == 0b01:
        return "SDCCH/8", v & 0x07
    return f"reserved({v:05b})", None


def channel_description(v: bytes) -> dict:
    """Channel Description (10.5.2.5), 3 octets."""
    if len(v) < 3:
        raise IEError("short channel description")
    ctype, sub = _chan_type(v[0] >> 3)
    out = {
        "channel": ctype,
        "subchannel": sub,
        "timeslot": v[0] & 0x07,
        "tsc": v[1] >> 5,
        "hopping": bool(v[1] & 0x10),
    }
    if out["hopping"]:
        out["maio"] = ((v[1] & 0x0F) << 2) | (v[2] >> 6)
        out["hsn"] = v[2] & 0x3F
    else:
        out["arfcn"] = ((v[1] & 0x03) << 8) | v[2]
    return out


def channel_description_2(v: bytes) -> dict:
    """Channel Description 2 (10.5.2.5a): like 10.5.2.5 plus TCH/F + SACCH/M and multislot types."""
    out = channel_description(v)
    t = v[0] >> 3
    if t == 0b00000:
        out["channel"], out["subchannel"] = "TCH/F (SACCH/M)", None
    elif t >> 4 == 1:
        out["channel"], out["subchannel"] = "TCH/F multislot", None
    return out


def packet_channel_description(v: bytes) -> dict:
    """Packet Channel Description (10.5.2.25a), 3 octets."""
    if len(v) < 3:
        raise IEError("short packet channel description")
    out = {
        "channel": "PDCH",
        "channel_type": v[0] >> 3,
        "timeslot": v[0] & 0x07,
        "tsc": v[1] >> 5,
        "hopping": bool(v[1] & 0x10),
    }
    if out["hopping"]:
        out["maio"] = ((v[1] & 0x0F) << 2) | (v[2] >> 6)
        out["hsn"] = v[2] & 0x3F
    else:
        out["arfcn"] = ((v[1] & 0x03) << 8) | v[2]
    return out


def request_reference(v: bytes) -> dict:
    """Request Reference (10.5.2.30): RA plus the reduced frame number of the access burst."""
    if len(v) < 3:
        raise IEError("short request reference")
    ra = v[0]
    t1 = v[1] >> 3
    t3 = ((v[1] & 0x07) << 3) | (v[2] >> 5)
    t2 = v[2] & 0x1F
    fn_mod = 51 * ((t3 - t2) % 26) + t3 + 51 * 26 * t1
    return {"ra": ra, "t1": t1, "t2": t2, "t3": t3, "fn_mod_42432": fn_mod}


def establishment_cause(ra: int, neci: bool | None = None) -> str:
    """Map an 8-bit RA value to its establishment cause (44.018 table 9.1.8.1).

    Some codes depend on the cell's NECI flag (SI3/SI4 cell selection parameters).
    """
    top3, top4 = ra >> 5, ra >> 4
    if top3 == 0b101:
        return "emergency call"
    if top3 == 0b110:
        return "call re-establishment (TCH/F)"
    if ra >> 2 == 0b011010:
        return "call re-establishment (TCH/H)"
    if ra >> 2 == 0b011011:
        return "call re-establishment (TCH/H + TCH/H)"
    if top3 == 0b100:
        return "answer to paging (any channel)"
    if top4 == 0b0010:
        return "answer to paging (TCH/F)"
    if top4 == 0b0011:
        return "answer to paging (TCH/H or TCH/F)"
    if top3 == 0b111:
        return "originating call" if neci else "originating call or SDCCH procedure"
    if top4 == 0b0100:
        return "originating speech call (TCH/H)"
    if top4 == 0b0101:
        return "originating data call (TCH/H)"
    if ra >> 3 == 0b01111:
        return "reserved" if ra == 0x7F else "packet access (one phase)"
    if ra >> 3 == 0b01110:
        return "packet access (single block)"
    if ra == 0b01100111:
        return "LMU establishment"
    if ra >> 3 == 0b01100:
        return "reserved"
    if top4 == 0b0001:
        # Shared by "answer to paging, SDCCH needed" and, with NECI set,
        # "other SDCCH procedure"; without NECI it also falls in 000xxxxx.
        if neci is False:
            return "location updating or answer to paging (SDCCH)"
        return "answer to paging (SDCCH) or other SDCCH procedure"
    return "location updating"


def timing_advance(v: int) -> dict:
    ta = v & 0x3F
    # One TA step is one bit period of round trip: 3.69 us * c / 2 = ~553.5 m.
    return {"ta": ta, "distance_m": round(ta * 553.5)}


# --- Frequency lists (44.018 10.5.2.13) ------------------------------------

def _range_widths(base: int):
    # W(1) has `base` bits, W(2..3) base-1, W(4..7) base-2, ...
    k = 1
    width = base
    while width > 0:
        for _ in range(k):
            yield width
        k *= 2
        width -= 1


def _read_ws(r: BitReader, base: int) -> list[int]:
    ws = [0]  # 1-based
    for width in _range_widths(base):
        try:
            w = r.bits(width)
        except BitsExhausted:
            break
        if w == 0:
            break
        ws.append(w)
    return ws


def _greatest_pow2_le(n: int) -> int:
    return 1 << (n.bit_length() - 1)


def _decode_range(ws: list[int], rng: int) -> list[int]:
    """Annex J tree decoding; returns F(K) values (1-based offsets)."""
    out = []
    for k in range(1, len(ws)):
        index = k
        j = _greatest_pow2_le(index)
        n = ws[index]
        while index > 1:
            if 2 * index < 3 * j:  # left child
                index -= j // 2
                n = (n + ws[index] - rng // j - 1) % (2 * rng // j - 1) + 1
            else:  # right child
                index -= j
                n = (n + ws[index] - 1) % (2 * rng // j - 1) + 1
            j //= 2
        out.append(n)
    return out


def frequency_list(v: bytes) -> list[int]:
    """Decode a 16-octet Cell Channel / Neighbour Cell Description into ARFCNs."""
    if len(v) < 1:
        return []
    b0 = v[0]
    arfcns: set[int] = set()
    if b0 & 0xC0 == 0x00:  # bit map 0
        if len(v) < 16:
            raise IEError("short bit map 0")
        for a in range(1, 125):
            if v[15 - ((a - 1) >> 3)] & (1 << ((a - 1) & 7)):
                arfcns.add(a)
        return sorted(arfcns)
    if b0 & 0xC8 == 0x80:  # 1024 range
        if b0 & 0x04:
            arfcns.add(0)
        r = BitReader(v, 6)
        ws = _read_ws(r, 10)
        arfcns.update(_decode_range(ws, 1024))
        return sorted(arfcns)
    fmt = b0 & 0xCE
    if fmt in (0x88, 0x8A, 0x8C):  # 512 / 256 / 128 range
        rng, base = {0x88: (512, 9), 0x8A: (256, 8), 0x8C: (128, 7)}[fmt]
        r = BitReader(v, 7)
        orig = r.bits(10)
        arfcns.add(orig)
        ws = _read_ws(r, base)
        for f in _decode_range(ws, rng):
            arfcns.add((orig + f) % 1024)
        return sorted(arfcns)
    if fmt == 0x8E:  # variable bit map
        r = BitReader(v, 7)
        orig = r.bits(10)
        arfcns.add(orig)
        k = 1
        while r.remaining > 0:
            if r.bit():
                arfcns.add((orig + k) % 1024)
            k += 1
        return sorted(arfcns)
    raise IEError(f"unknown frequency list format 0x{b0:02x}")
