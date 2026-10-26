"""GSMTAP header parsing (osmocom gsmtap.h, version 2)."""

from __future__ import annotations

import struct
from dataclasses import dataclass

GSMTAP_PORT = 4729
GSMTAP_HDR_MIN = 16

# GSMTAP payload types
TYPE_UM = 0x01
TYPE_ABIS = 0x02
TYPE_UM_BURST = 0x03
TYPE_SIM = 0x04
TYPE_GB_LLC = 0x08
TYPE_GB_SNDCP = 0x09
TYPE_UMTS_RRC = 0x0C
TYPE_LTE_RRC = 0x0D
TYPE_LTE_MAC = 0x0E
TYPE_LTE_NAS = 0x12

TYPE_NAMES = {
    TYPE_UM: "UM",
    TYPE_ABIS: "ABIS",
    TYPE_UM_BURST: "UM_BURST",
    TYPE_SIM: "SIM",
    TYPE_GB_LLC: "GB_LLC",
    TYPE_GB_SNDCP: "GB_SNDCP",
    TYPE_UMTS_RRC: "UMTS_RRC",
    TYPE_LTE_RRC: "LTE_RRC",
    TYPE_LTE_MAC: "LTE_MAC",
    TYPE_LTE_NAS: "LTE_NAS",
}

# Um logical channel sub types
CH_UNKNOWN = 0x00
CH_BCCH = 0x01
CH_CCCH = 0x02
CH_RACH = 0x03
CH_AGCH = 0x04
CH_PCH = 0x05
CH_SDCCH = 0x06
CH_SDCCH4 = 0x07
CH_SDCCH8 = 0x08
CH_TCH_F = 0x09
CH_TCH_H = 0x0A
CH_PACCH = 0x0B
CH_CBCH52 = 0x0C
CH_PDCH = 0x0D
CH_PTCCH = 0x0E
CH_CBCH51 = 0x0F
CH_VOICE_F = 0x10
CH_VOICE_H = 0x11
CH_ACCH = 0x80

CHANNEL_NAMES = {
    CH_UNKNOWN: "UNKNOWN",
    CH_BCCH: "BCCH",
    CH_CCCH: "CCCH",
    CH_RACH: "RACH",
    CH_AGCH: "AGCH",
    CH_PCH: "PCH",
    CH_SDCCH: "SDCCH",
    CH_SDCCH4: "SDCCH/4",
    CH_SDCCH8: "SDCCH/8",
    CH_TCH_F: "TCH/F",
    CH_TCH_H: "TCH/H",
    CH_PACCH: "PACCH",
    CH_CBCH52: "CBCH/52",
    CH_PDCH: "PDCH",
    CH_PTCCH: "PTCCH",
    CH_CBCH51: "CBCH/51",
    CH_VOICE_F: "VOICE/F",
    CH_VOICE_H: "VOICE/H",
}

# Channels that carry Bbis frames (L2 pseudo length + L3, no LAPDm)
BBIS_CHANNELS = frozenset({CH_BCCH, CH_CCCH, CH_AGCH, CH_PCH})
DEDICATED_CHANNELS = frozenset({CH_SDCCH, CH_SDCCH4, CH_SDCCH8, CH_TCH_F, CH_TCH_H})

ARFCN_F_PCS = 0x8000
ARFCN_F_UPLINK = 0x4000
ARFCN_MASK = 0x3FFF

_HDR = struct.Struct("!BBBBHbbIBBBB")


class GsmtapError(ValueError):
    pass


@dataclass(slots=True)
class GsmtapHeader:
    version: int
    type: int
    timeslot: int
    arfcn: int
    pcs: bool
    uplink: bool
    signal_dbm: int
    snr_db: int
    frame_number: int
    channel: int
    acch: bool
    antenna: int
    sub_slot: int

    @property
    def channel_name(self) -> str:
        name = CHANNEL_NAMES.get(self.channel, f"0x{self.channel:02x}")
        return f"SACCH({name})" if self.acch else name


def parse_header(buf: bytes) -> tuple[GsmtapHeader, memoryview]:
    """Return the header and a view of the payload that follows it."""
    if len(buf) < GSMTAP_HDR_MIN:
        raise GsmtapError("short GSMTAP packet")
    (version, hdr_words, typ, ts, arfcn, sig, snr, fn,
     sub_type, antenna, sub_slot, _res) = _HDR.unpack_from(buf)
    if version not in (1, 2):
        raise GsmtapError(f"unsupported GSMTAP version {version}")
    hdr_len = hdr_words * 4
    if hdr_len < GSMTAP_HDR_MIN or hdr_len > len(buf):
        raise GsmtapError(f"bad GSMTAP header length {hdr_len}")
    hdr = GsmtapHeader(
        version=version,
        type=typ,
        timeslot=ts,
        arfcn=arfcn & ARFCN_MASK,
        pcs=bool(arfcn & ARFCN_F_PCS),
        uplink=bool(arfcn & ARFCN_F_UPLINK),
        signal_dbm=sig,
        snr_db=snr,
        frame_number=fn,
        channel=sub_type & 0x7F,
        acch=bool(sub_type & CH_ACCH),
        antenna=antenna,
        sub_slot=sub_slot,
    )
    return hdr, memoryview(buf)[hdr_len:]


def build_header(
    arfcn: int,
    channel: int,
    *,
    timeslot: int = 0,
    frame_number: int = 0,
    signal_dbm: int = 0,
    snr_db: int = 0,
    sub_slot: int = 0,
    acch: bool = False,
    uplink: bool = False,
    pcs: bool = False,
    typ: int = TYPE_UM,
) -> bytes:
    a = arfcn & ARFCN_MASK
    if uplink:
        a |= ARFCN_F_UPLINK
    if pcs:
        a |= ARFCN_F_PCS
    sub = channel | (CH_ACCH if acch else 0)
    return _HDR.pack(2, 4, typ, timeslot, a, signal_dbm, snr_db, frame_number, sub, 0, sub_slot, 0)
