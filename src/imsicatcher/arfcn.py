"""ARFCN to frequency mapping for GSM bands (3GPP TS 45.005 section 2)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Band:
    name: str
    first: int
    last: int
    ul_base: float  # uplink MHz at `first`
    duplex: float  # downlink minus uplink, MHz


# Order matters: the first match wins, so PCS (only when flagged) is handled separately.
BANDS = (
    Band("GSM450", 259, 293, 450.6, 10.0),
    Band("GSM480", 306, 340, 479.0, 10.0),
    Band("GSM750", 438, 511, 747.2, 30.0),
    Band("GSM850", 128, 251, 824.2, 45.0),
    Band("P-GSM900", 1, 124, 890.2, 45.0),
    Band("DCS1800", 512, 885, 1710.2, 95.0),
)
PCS1900 = Band("PCS1900", 512, 810, 1850.2, 80.0)


def band_of(arfcn: int, pcs: bool = False) -> str | None:
    if pcs and 512 <= arfcn <= 810:
        return PCS1900.name
    if arfcn == 0 or 975 <= arfcn <= 1023:
        return "E-GSM900"
    if 955 <= arfcn <= 974:
        return "R-GSM900"
    if 940 <= arfcn <= 954:
        return "ER-GSM900"
    for b in BANDS:
        if b.first <= arfcn <= b.last:
            return b.name
    return None


def uplink_mhz(arfcn: int, pcs: bool = False) -> float | None:
    if pcs and 512 <= arfcn <= 810:
        return round(PCS1900.ul_base + 0.2 * (arfcn - 512), 1)
    if arfcn == 0:
        return 890.0
    if 940 <= arfcn <= 1023:
        return round(890.0 + 0.2 * (arfcn - 1024), 1)
    for b in BANDS:
        if b.first <= arfcn <= b.last:
            return round(b.ul_base + 0.2 * (arfcn - b.first), 1)
    return None


def downlink_mhz(arfcn: int, pcs: bool = False) -> float | None:
    ul = uplink_mhz(arfcn, pcs)
    if ul is None:
        return None
    if pcs and 512 <= arfcn <= 810:
        return round(ul + PCS1900.duplex, 1)
    if arfcn == 0 or 940 <= arfcn <= 1023:
        return round(ul + 45.0, 1)
    for b in BANDS:
        if b.first <= arfcn <= b.last:
            return round(ul + b.duplex, 1)
    return None


def arfcn_from_downlink(mhz: float, pcs: bool = False) -> int | None:
    """Inverse of downlink_mhz; returns None if the frequency is not on the 200 kHz raster."""
    candidates = [PCS1900] if pcs else []
    for arfcn in _all_arfcns(candidates):
        f = downlink_mhz(arfcn, pcs and 512 <= arfcn <= 810)
        if f is not None and abs(f - mhz) < 0.05:
            return arfcn
    return None


def _all_arfcns(extra):
    for b in extra:
        yield from range(b.first, b.last + 1)
    yield 0
    for b in BANDS:
        yield from range(b.first, b.last + 1)
    yield from range(940, 1024)


def parse_frequency(text: str) -> float:
    """Parse '947.2M', '947200000', '947.2e6' or '1842.6MHz' into Hz."""
    t = text.strip().lower().removesuffix("hz")
    mult = 1.0
    if t.endswith("g"):
        mult, t = 1e9, t[:-1]
    elif t.endswith("m"):
        mult, t = 1e6, t[:-1]
    elif t.endswith("k"):
        mult, t = 1e3, t[:-1]
    value = float(t) * mult
    if value < 1e5:  # bare MHz value such as "947.2"
        value *= 1e6
    return value


# UMTS FDD downlink UARFCN ranges: (band, first, last, offset MHz); f = offset + UARFCN / 5.
_UMTS_BANDS = (
    ("B1", 10562, 10838, 0.0),
    ("B2", 9662, 9938, 0.0),
    ("B4", 1537, 1738, 1805.0),
    ("B5", 4357, 4458, 0.0),
    ("B8", 2937, 3088, 340.0),
)


def uarfcn_info(uarfcn: int) -> tuple[str | None, float | None]:
    """(UMTS band, downlink MHz) for a downlink UARFCN in the common FDD bands."""
    for name, first, last, offset in _UMTS_BANDS:
        if first <= uarfcn <= last:
            return name, round(offset + uarfcn / 5, 1)
    return None, None
