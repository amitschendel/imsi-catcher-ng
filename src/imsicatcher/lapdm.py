"""LAPDm (3GPP TS 44.006) frame parsing and I-frame reassembly."""

from __future__ import annotations

from dataclasses import dataclass

U_FUNCS = {
    0x03: "UI",
    0x0F: "DM",
    0x2F: "SABM",
    0x43: "DISC",
    0x63: "UA",
}
S_FUNCS = ("RR", "RNR", "REJ", "SREJ")

MAX_REASSEMBLY = 251


@dataclass(slots=True)
class LapdmFrame:
    sapi: int
    cr: int
    kind: str  # "I", "S" or "U"
    func: str  # UI/SABM/UA/DISC/DM, RR/RNR/REJ, or "I"
    ns: int
    nr: int
    pf: int
    more: bool
    info: bytes
    tail: bytes  # octets after the information field (SACCH rest octets)


def parse_frame(data: bytes) -> LapdmFrame | None:
    """Parse a format A/B LAPDm frame (address, control, length, info)."""
    if len(data) < 3:
        return None
    addr, ctrl, length = data[0], data[1], data[2]
    if not addr & 0x01 or not length & 0x01:
        return None
    sapi = (addr >> 2) & 0x07
    cr = (addr >> 1) & 0x01
    pf = (ctrl >> 4) & 0x01
    ns = nr = 0
    if not ctrl & 0x01:
        kind, func = "I", "I"
        ns = (ctrl >> 1) & 0x07
        nr = (ctrl >> 5) & 0x07
    elif ctrl & 0x03 == 0x01:
        kind = "S"
        func = S_FUNCS[(ctrl >> 2) & 0x03]
        nr = (ctrl >> 5) & 0x07
    else:
        kind = "U"
        func = U_FUNCS.get(ctrl & 0xEF, f"U(0x{ctrl:02x})")
    n = length >> 2
    more = bool(length & 0x02)
    info = bytes(data[3:3 + n]) if n else b""
    if len(info) != n:
        return None
    return LapdmFrame(sapi, cr, kind, func, ns, nr, pf, more, info, bytes(data[3 + n:]))


class _Link:
    __slots__ = ("vr", "buf", "skip")

    def __init__(self, vr: int | None) -> None:
        self.vr = vr  # next expected N(S); None until the link is in sync
        self.buf: bytearray | None = None
        self.skip = False  # discarding the rest of a message whose start was lost


class Reassembler:
    """Joins segmented I frames (M bit set) per logical link, tracking V(R).

    Retransmitted frames (N(S) = V(R) - 1) are ignored, and after a gap the
    remaining segments of the broken message are dropped rather than decoded
    as if they started a message.
    """

    __slots__ = ("_links",)

    def __init__(self) -> None:
        self._links: dict[tuple, _Link] = {}

    def reset(self, link: tuple) -> None:
        """Link (re)established by SABM/UA: sequence numbers restart at 0."""
        self._links[link] = _Link(0)

    def release(self, link: tuple) -> None:
        self._links.pop(link, None)

    def push(self, link: tuple, frame: LapdmFrame) -> bytes | None:
        """Feed an I frame; return the complete L3 message once the last segment arrives."""
        st = self._links.get(link)
        if st is None:
            # Joined mid-conversation: a segment with M set may be a middle one.
            st = self._links[link] = _Link(None)
            st.skip = frame.more
        elif st.vr is not None:
            if frame.ns == (st.vr - 1) & 0x07:
                return None  # retransmission of the frame we already have
            if frame.ns != st.vr:
                st.buf = None
                st.skip = True
        st.vr = (frame.ns + 1) & 0x07
        if st.skip:
            if not frame.more:
                st.skip = False
            return None
        if frame.more:
            if st.buf is None:
                st.buf = bytearray()
            st.buf.extend(frame.info)
            if len(st.buf) > MAX_REASSEMBLY:
                st.buf = None
                st.skip = True
            return None
        if st.buf is None:
            return frame.info
        st.buf.extend(frame.info)
        out = bytes(st.buf)
        st.buf = None
        return out
