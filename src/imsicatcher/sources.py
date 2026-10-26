"""Packet sources: live GSMTAP over UDP, interface sniffing, and pcap/pcapng files."""

from __future__ import annotations

import selectors
import socket
import struct
import time
from collections.abc import Iterator
from pathlib import Path

from .gsmtap import GSMTAP_PORT

Packet = tuple[float, bytes]  # (unix timestamp, GSMTAP datagram)

# pcap link types
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LOOP = 108
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276


def _udp_payload_from_ip(data: bytes, ports: frozenset[int] | None) -> bytes | None:
    if not data:
        return None
    ver = data[0] >> 4
    if ver == 4:
        ihl = (data[0] & 0x0F) * 4
        if len(data) < ihl + 8 or data[9] != 17:
            return None
        # Fragmented datagrams are not reassembled; GSMTAP packets are tiny.
        if struct.unpack_from("!H", data, 6)[0] & 0x3FFF:
            return None
        udp = ihl
    elif ver == 6:
        if len(data) < 48 or data[6] != 17:
            return None
        udp = 40
    else:
        return None
    sport, dport, ulen = struct.unpack_from("!HHH", data, udp)
    if ports is not None and dport not in ports and sport not in ports:
        return None
    return bytes(data[udp + 8:udp + max(ulen, 8)])


def _strip_link(linktype: int, frame: bytes) -> bytes | None:
    if linktype == LINKTYPE_ETHERNET:
        off, ethertype = 14, struct.unpack_from("!H", frame, 12)[0] if len(frame) >= 14 else 0
        while ethertype in (0x8100, 0x88A8) and len(frame) >= off + 4:
            ethertype = struct.unpack_from("!H", frame, off + 2)[0]
            off += 4
        return frame[off:] if ethertype in (0x0800, 0x86DD) else None
    if linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        return frame
    if linktype in (LINKTYPE_NULL, LINKTYPE_LOOP):
        return frame[4:]
    if linktype == LINKTYPE_LINUX_SLL:
        return frame[16:]
    if linktype == LINKTYPE_LINUX_SLL2:
        return frame[20:]
    return None


def read_capture(path: str | Path, ports: frozenset[int] | None = frozenset({GSMTAP_PORT})) -> Iterator[Packet]:
    """Yield GSMTAP datagrams from a pcap or pcapng file."""
    with open(path, "rb") as f:
        magic = f.read(4)
        f.seek(0)
        if magic == b"\x0a\x0d\x0d\x0a":
            yield from _read_pcapng(f, ports)
        else:
            yield from _read_pcap(f, ports)


def _read_pcap(f, ports) -> Iterator[Packet]:
    hdr = f.read(24)
    if len(hdr) < 24:
        return
    magic = hdr[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError("not a pcap or pcapng file")
    nanos = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack(endian + "I", hdr[20:24])[0] & 0x0FFFFFFF
    rec = struct.Struct(endian + "IIII")
    div = 1e9 if nanos else 1e6
    while True:
        h = f.read(16)
        if len(h) < 16:
            return
        sec, frac, incl, _orig = rec.unpack(h)
        frame = f.read(incl)
        if len(frame) < incl:
            return
        ip = _strip_link(linktype, frame)
        if ip is None:
            continue
        payload = _udp_payload_from_ip(ip, ports)
        if payload is not None:
            yield sec + frac / div, payload


def _read_pcapng(f, ports) -> Iterator[Packet]:
    endian = "<"
    interfaces: list[tuple[int, float]] = []  # (linktype, ticks per second)
    while True:
        head = f.read(8)
        if len(head) < 8:
            return
        btype, blen = struct.unpack(endian + "II", head)
        if btype == 0x0A0D0D0A:
            bom = f.read(4)
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(endian + "I", head[4:])[0]
            body = bom + f.read(blen - 12)
            interfaces = []
        else:
            body = f.read(blen - 8)
        if len(body) < blen - 8:
            return
        if btype == 1:  # Interface Description Block
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            tsres = 1e6
            off = 8
            while off + 4 <= len(body) - 4:
                code, olen = struct.unpack_from(endian + "HH", body, off)
                if code == 0:
                    break
                if code == 9 and olen >= 1:
                    v = body[off + 4]
                    tsres = float(2 ** (v & 0x7F)) if v & 0x80 else float(10 ** v)
                off += 4 + ((olen + 3) & ~3)
            interfaces.append((linktype, tsres))
        elif btype == 6:  # Enhanced Packet Block
            iface, ts_hi, ts_lo, cap = struct.unpack_from(endian + "IIII", body, 0)
            if iface >= len(interfaces):
                continue
            linktype, tsres = interfaces[iface]
            frame = body[20:20 + cap]
            ip = _strip_link(linktype, frame)
            if ip is None:
                continue
            payload = _udp_payload_from_ip(ip, ports)
            if payload is not None:
                yield ((ts_hi << 32) | ts_lo) / tsres, payload
        elif btype == 3 and interfaces:  # Simple Packet Block
            linktype, _ = interfaces[0]
            ip = _strip_link(linktype, body[4:])
            if ip is None:
                continue
            payload = _udp_payload_from_ip(ip, ports)
            if payload is not None:
                yield time.time(), payload


class UdpSource:
    """Receive GSMTAP datagrams on one or more UDP sockets."""

    def __init__(self, endpoints: list[tuple[str, int]], rcvbuf: int = 4 << 20) -> None:
        self.selector = selectors.DefaultSelector()
        self.sockets = []
        for host, port in endpoints:
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            s = socket.socket(family, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
            except OSError:
                pass
            s.bind((host, port))
            s.setblocking(False)
            self.selector.register(s, selectors.EVENT_READ)
            self.sockets.append(s)

    def packets(self, timeout: float = 0.25) -> Iterator[Packet | None]:
        """Yield packets forever; yields None on idle timeouts so callers can do housekeeping."""
        while True:
            events = self.selector.select(timeout)
            if not events:
                yield None
                continue
            now = time.time()
            for key, _ in events:
                sock = key.fileobj
                # Drain everything queued on this socket before selecting again.
                while True:
                    try:
                        data = sock.recv(65535)
                    except BlockingIOError:
                        break
                    yield now, data

    def close(self) -> None:
        for s in self.sockets:
            self.selector.unregister(s)
            s.close()


class SniffSource:
    """Linux AF_PACKET capture of GSMTAP on an interface (needs CAP_NET_RAW).

    Useful when another program already owns the UDP port.
    """

    ETH_P_ALL = 0x0003

    def __init__(self, iface: str, ports: frozenset[int] = frozenset({GSMTAP_PORT})) -> None:
        if not hasattr(socket, "AF_PACKET"):
            raise OSError("interface sniffing needs Linux AF_PACKET")
        self.ports = ports
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(self.ETH_P_ALL))
        self.sock.bind((iface, 0))
        self.sock.settimeout(0.25)

    def packets(self) -> Iterator[Packet | None]:
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
            except TimeoutError:
                yield None
                continue
            # On loopback each packet is seen twice (outgoing and incoming).
            if addr[2] == socket.PACKET_OUTGOING:
                continue
            payload = _udp_payload_from_ip(data, self.ports)
            if payload is not None:
                yield time.time(), payload

    def close(self) -> None:
        self.sock.close()


class PcapWriter:
    """Write GSMTAP datagrams as a pcap (raw IPv4/UDP) that Wireshark can open."""

    def __init__(self, path: str | Path, port: int = GSMTAP_PORT) -> None:
        self.f = open(path, "wb")
        self.port = port
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_IPV4))

    def write(self, ts: float, datagram: bytes) -> None:
        udp = struct.pack("!HHHH", self.port, self.port, 8 + len(datagram), 0) + datagram
        total = 20 + len(udp)
        ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, 17, 0,
                                   b"\x7f\x00\x00\x01", b"\x7f\x00\x00\x01"))
        s = sum(struct.unpack("!10H", ip))
        s = (s & 0xFFFF) + (s >> 16)
        s = (s & 0xFFFF) + (s >> 16)
        struct.pack_into("!H", ip, 10, ~s & 0xFFFF)
        sec = int(ts)
        self.f.write(struct.pack("<IIII", sec, int((ts - sec) * 1e6), total, total))
        self.f.write(ip)
        self.f.write(udp)

    def flush(self) -> None:
        self.f.flush()

    def close(self) -> None:
        self.f.close()
