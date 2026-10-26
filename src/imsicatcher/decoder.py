"""GSMTAP datagram to decoded L3 messages."""

from __future__ import annotations

from dataclasses import dataclass, field

from . import gsmtap, mm, rr
from .gsmtap import GsmtapError, GsmtapHeader
from .lapdm import LapdmFrame, Reassembler, parse_frame

PD_NAMES = {
    0x0: "GCC",
    0x1: "BCC",
    0x2: "PDSS1",
    0x3: "CC",
    0x4: "PDSS2",
    0x5: "MM",
    0x6: "RR",
    0x8: "GMM",
    0x9: "SMS",
    0xA: "SM",
    0xB: "SS",
    0xC: "LCS",
}
CC_NAMES = {
    0x01: "Alerting",
    0x02: "Call Proceeding",
    0x03: "Progress",
    0x05: "Setup",
    0x07: "Connect",
    0x08: "Call Confirmed",
    0x0F: "Connect Acknowledge",
    0x25: "Disconnect",
    0x2A: "Release Complete",
    0x2D: "Release",
    0x34: "Status Enquiry",
    0x3D: "Status",
}

# RR messages with the short protocol discriminator (44.018 10.4a), sent on SACCH.
SHORT_PD_NAMES = {
    0x00: "System Information Type 10",
    0x01: "Notification/FACCH",
    0x02: "Uplink Free",
    0x04: "Enhanced Measurement Report",
    0x05: "Measurement Information",
    0x06: "VBS/VGCS Reconfigure",
    0x07: "VBS/VGCS Reconfigure2",
    0x08: "VGCS Additional Information",
    0x09: "VGCS SMS Information",
    0x0A: "System Information Type 10bis",
    0x0B: "System Information Type 10ter",
    0x0C: "VGCS Neighbour Cell Information",
    0x0D: "Notify Application Data",
}

_CACHE_LIMIT = 8192


@dataclass(slots=True)
class Decoded:
    hdr: GsmtapHeader
    frame: LapdmFrame | None = None
    sacch: dict | None = None
    messages: list[dict] = field(default_factory=list)
    error: str | None = None


def decode_l3(body: bytes, rest: bytes = b"") -> dict | None:
    if len(body) < 2:
        return None
    pd = body[0] & 0x0F
    if pd == 0x6:
        return rr.decode(body, rest)
    if pd == 0x5:
        return mm.decode(body)
    mt = body[1] & 0x3F
    name = PD_NAMES.get(pd, f"PD {pd}")
    if pd == 0x3:
        return {"pd": "CC", "mt": mt, "name": CC_NAMES.get(mt, f"CC 0x{mt:02x}")}
    # User-plane bearing protocols (SMS, SS, ...) are identified but not decoded.
    return {"pd": name, "mt": body[1], "name": f"{name} message"}


def decode_bbis(payload: bytes) -> dict | None:
    """Bbis frame: L2 pseudo length octet followed by L3 and rest octets."""
    if len(payload) < 3:
        return None
    pl = payload[0]
    if pl & 0x03 != 0x01:
        return None
    n = pl >> 2
    if n + 1 > len(payload):
        return None
    # SI13 and SI2quater use a pseudo length of 0 or 1: everything after the
    # message type is rest octets.
    end = max(n, 2) + 1
    body = payload[1:end]
    if body[0] & 0x0F != 0x6:
        return None
    return rr.decode(body, payload[end:])


class Decoder:
    """Stateful decoder: owns LAPDm reassembly and a cache for repeated broadcast blocks."""

    def __init__(self) -> None:
        self.reassembler = Reassembler()
        self._bbis_cache: dict[bytes, dict | None] = {}
        self.stats = {"packets": 0, "errors": 0, "cache_hits": 0}

    def decode(self, datagram: bytes) -> Decoded | None:
        self.stats["packets"] += 1
        try:
            hdr, payload = gsmtap.parse_header(datagram)
        except GsmtapError:
            self.stats["errors"] += 1
            return None
        if hdr.type != gsmtap.TYPE_UM:
            return Decoded(hdr)
        out = Decoded(hdr)
        ch = hdr.channel
        if ch in gsmtap.BBIS_CHANNELS and not hdr.acch:
            key = bytes(payload)
            cache = self._bbis_cache
            if key in cache:
                self.stats["cache_hits"] += 1
                msg = cache[key]
            else:
                msg = decode_bbis(key)
                if len(cache) >= _CACHE_LIMIT:
                    cache.clear()
                cache[key] = msg
            if msg is not None:
                out.messages.append(msg)
            return out
        if ch in gsmtap.DEDICATED_CHANNELS:
            self._decode_dedicated(hdr, bytes(payload), out)
        return out

    def _decode_dedicated(self, hdr: GsmtapHeader, payload: bytes, out: Decoded) -> None:
        if hdr.acch:
            if len(payload) < 5:
                return
            # SACCH L1 header: ordered MS power level and timing advance.
            out.sacch = {"ms_power": payload[0] & 0x1F, "fpc": bool(payload[0] & 0x20),
                         "ta": payload[1] & 0x7F}
            payload = payload[2:]
            if payload[0] & 0x83 == 0x00:
                # Short L2 header (format Bter) carrying a short-PD RR message.
                mt = (payload[0] >> 2) & 0x1F
                out.messages.append({"pd": "RR", "mt": mt, "short_pd": True,
                                     "name": SHORT_PD_NAMES.get(mt, f"RR short PD 0x{mt:02x}")})
                return
        frame = parse_frame(payload)
        if frame is None or frame.sapi not in (0, 3) or payload[0] & 0x60:
            out.error = "not a valid LAPDm frame"
            return
        out.frame = frame
        link = (hdr.arfcn, hdr.timeslot, hdr.channel, hdr.sub_slot, hdr.acch, frame.sapi, hdr.uplink)
        if frame.sapi == 3:
            if frame.info:
                out.messages.append({"pd": "SMS", "mt": None, "name": "SMS (SAPI 3)"})
            return
        if frame.kind == "U":
            if frame.func in ("SABM", "UA"):
                self.reassembler.reset(link)
            elif frame.func in ("DISC", "DM"):
                self.reassembler.release(link)
            if frame.info:
                msg = decode_l3(frame.info, frame.tail)
                if msg is not None:
                    out.messages.append(msg)
            return
        if frame.kind == "I":
            l3 = self.reassembler.push(link, frame)
            if l3:
                msg = decode_l3(l3)
                if msg is not None:
                    out.messages.append(msg)
