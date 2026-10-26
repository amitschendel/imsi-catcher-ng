"""Synthetic GSMTAP messages with known contents.

Every builder returns (datagram, expected) where `expected` holds the values
the decoder should report. Identities are random, never real.
"""

from __future__ import annotations

import random

from imsicatcher import gsmtap

PAD = 0x2B


def bbis(l3: bytes, rest: bytes = b"", pseudo_len: int | None = None) -> bytes:
    n = len(l3) if pseudo_len is None else pseudo_len
    body = bytes([(n << 2) | 0x01]) + l3 + rest
    return body + bytes([PAD]) * (23 - len(body))


def lapdm(info: bytes, *, ctrl: int, sapi: int = 0, cr: int = 1, more: bool = False, size: int = 23) -> bytes:
    addr = (sapi << 2) | (cr << 1) | 0x01
    length = (len(info) << 2) | (0x02 if more else 0) | 0x01
    body = bytes([addr, ctrl, length]) + info
    return body + bytes([PAD]) * (size - len(body))


def ua(info: bytes) -> bytes:
    return lapdm(info, ctrl=0x73)


def iframe(info: bytes, ns: int = 0, nr: int = 1, more: bool = False) -> bytes:
    return lapdm(info, ctrl=(nr << 5) | (ns << 1), more=more)


def gsmtap_pkt(payload: bytes, channel: int, arfcn: int = 61, **kw) -> bytes:
    return gsmtap.build_header(arfcn, channel, **kw) + payload


def encode_digits(kind: int, digits: str) -> bytes:
    odd = len(digits) % 2
    out = [(int(digits[0]) << 4) | (0x08 if odd else 0) | kind]
    rest = [int(d) for d in digits[1:]]
    if not odd:
        rest.append(0x0F)
    for i in range(0, len(rest), 2):
        out.append(rest[i] | (rest[i + 1] << 4))
    return bytes(out)


def mi_imsi(digits: str) -> bytes:
    return encode_digits(1, digits)


def mi_imei(digits: str) -> bytes:
    return encode_digits(2, digits)


def mi_tmsi(tmsi: bytes) -> bytes:
    return b"\xf4" + tmsi


def lv(v: bytes) -> bytes:
    return bytes([len(v)]) + v


def plmn_bytes(mcc: str, mnc: str) -> bytes:
    m3 = int(mnc[2]) if len(mnc) == 3 else 0x0F
    return bytes([int(mcc[1]) << 4 | int(mcc[0]), m3 << 4 | int(mcc[2]), int(mnc[1]) << 4 | int(mnc[0])])


def lai_bytes(mcc: str, mnc: str, lac: int) -> bytes:
    return plmn_bytes(mcc, mnc) + lac.to_bytes(2, "big")


class Gen:
    def __init__(self, seed: int = 1) -> None:
        self.rng = random.Random(seed)

    def digits(self, n: int) -> str:
        return "".join(self.rng.choice("0123456789") for _ in range(n))

    def imsi(self) -> str:
        return self.rng.choice(["425", "208", "310", "262", "724"]) + self.digits(self.rng.choice([11, 12]))

    def imei(self) -> str:
        body = self.digits(14)
        total = 0
        for i, ch in enumerate(reversed(body)):
            d = int(ch)
            if i % 2 == 0:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
        return body + str((10 - total % 10) % 10)

    def tmsi(self) -> bytes:
        return self.rng.randbytes(4)

    def identity(self, allow=("imsi", "tmsi", "imei", "none")):
        kind = self.rng.choice(allow)
        if kind == "imsi":
            v = self.imsi()
            return mi_imsi(v), {"kind": "imsi", "value": v}
        if kind == "imei":
            v = self.imei()
            return mi_imei(v), {"kind": "imei", "value": v}
        if kind == "tmsi":
            t = self.tmsi()
            return mi_tmsi(t), {"kind": "tmsi", "value": t.hex().upper()}
        return b"\xf0", {"kind": "none", "value": None}

    # --- CCCH ---------------------------------------------------------------

    def paging1(self):
        mi1, e1 = self.identity()
        l3 = bytes([0x06, 0x21, self.rng.randrange(256) & 0xF3]) + lv(mi1)
        ids = [e1]
        if self.rng.random() < 0.5 and len(l3) + 2 + 9 <= 22:
            mi2, e2 = self.identity(("imsi", "tmsi"))
            l3 += b"\x17" + lv(mi2)
            ids.append(e2)
        expected = {"name": "Paging Request Type 1", "identities": [i for i in ids if i["kind"] != "none"]}
        return gsmtap_pkt(bbis(l3), gsmtap.CH_CCCH), expected

    def paging2(self):
        t1, t2 = self.tmsi(), self.tmsi()
        l3 = bytes([0x06, 0x22, 0x00]) + t1 + t2
        ids = [{"kind": "tmsi", "value": t.hex().upper()} for t in (t1, t2)]
        if self.rng.random() < 0.5:
            mi3, e3 = self.identity(("imsi", "tmsi"))
            l3 += b"\x17" + lv(mi3)
            ids.append(e3)
        return gsmtap_pkt(bbis(l3), gsmtap.CH_CCCH), {"name": "Paging Request Type 2", "identities": ids}

    def paging3(self):
        ts = [self.tmsi() for _ in range(4)]
        l3 = bytes([0x06, 0x24, 0x00]) + b"".join(ts)
        ids = [{"kind": "tmsi", "value": t.hex().upper()} for t in ts]
        return gsmtap_pkt(bbis(l3), gsmtap.CH_CCCH), {"name": "Paging Request Type 3", "identities": ids}

    def chan_desc(self):
        kind = self.rng.choice(["SDCCH/8", "SDCCH/4", "TCH/F", "TCH/H"])
        sub = {"SDCCH/8": self.rng.randrange(8), "SDCCH/4": self.rng.randrange(4),
               "TCH/H": self.rng.randrange(2), "TCH/F": None}[kind]
        ct = {"SDCCH/8": 0b01000 | (sub or 0), "SDCCH/4": 0b00100 | (sub or 0),
              "TCH/H": 0b00010 | (sub or 0), "TCH/F": 0b00001}[kind]
        tn = self.rng.randrange(8)
        tsc = self.rng.randrange(8)
        hop = self.rng.random() < 0.3
        exp = {"channel": kind, "subchannel": sub, "timeslot": tn, "tsc": tsc, "hopping": hop}
        if hop:
            maio, hsn = self.rng.randrange(64), self.rng.randrange(64)
            b = bytes([ct << 3 | tn, tsc << 5 | 0x10 | maio >> 2, (maio & 3) << 6 | hsn])
            exp.update(maio=maio, hsn=hsn)
        else:
            a = self.rng.randrange(1024)
            b = bytes([ct << 3 | tn, tsc << 5 | a >> 8, a & 0xFF])
            exp["arfcn"] = a
        return b, exp

    def req_ref(self):
        ra = self.rng.randrange(256)
        t1, t2, t3 = self.rng.randrange(32), self.rng.randrange(26), self.rng.randrange(51)
        b = bytes([ra, t1 << 3 | t3 >> 3, (t3 & 7) << 5 | t2])
        return b, {"ra": ra, "t1": t1, "t2": t2, "t3": t3}

    def ia(self):
        cd, ecd = self.chan_desc()
        rr_, er = self.req_ref()
        ta = self.rng.randrange(64)
        l3 = bytes([0x06, 0x3F, 0x00]) + cd + rr_ + bytes([ta]) + b"\x00"
        exp = {"name": "Immediate Assignment", "channel": ecd, "request_reference": er, "ta": ta}
        return gsmtap_pkt(bbis(l3), gsmtap.CH_CCCH), exp

    def iax(self):
        parts, exp = b"", []
        for _ in range(2):
            cd, ecd = self.chan_desc()
            rr_, er = self.req_ref()
            ta = self.rng.randrange(64)
            parts += cd + rr_ + bytes([ta])
            exp.append({"channel": ecd, "request_reference": er, "ta": ta})
        l3 = bytes([0x06, 0x39, 0x00]) + parts + b"\x00"
        return gsmtap_pkt(bbis(l3), gsmtap.CH_CCCH), {"name": "Immediate Assignment Extended", "assignments": exp}

    def iar(self):
        parts, exp = b"", []
        for _ in range(4):
            rr_, er = self.req_ref()
            w = self.rng.randrange(256)
            parts += rr_ + bytes([w])
            er["wait_indication_s"] = w
            exp.append(er)
        l3 = bytes([0x06, 0x3A, 0x00]) + parts
        return gsmtap_pkt(bbis(l3), gsmtap.CH_CCCH), {"name": "Immediate Assignment Reject", "rejects": exp}

    def freq_list(self, fmt: str, extra_bits: int = 0) -> bytes:
        body = self.rng.randbytes(15)
        r = self.rng.randrange(256)
        first = {
            "bitmap0": r & 0x0F,
            "1024": 0x80 | (r & 0x07),
            "512": 0x88 | (r & 0x01),
            "256": 0x8A | (r & 0x01),
            "128": 0x8C | (r & 0x01),
            "variable": 0x8E | (r & 0x01),
        }[fmt]
        return bytes([first | extra_bits]) + body

    def si1(self, fmt: str):
        l3 = bytes([0x06, 0x19]) + self.freq_list(fmt) + bytes([self.rng.randrange(256), 0, 0])
        return gsmtap_pkt(bbis(l3), gsmtap.CH_BCCH), {"name": "System Information Type 1"}

    def si2(self, fmt: str):
        l3 = bytes([0x06, 0x1A]) + self.freq_list(fmt, self.rng.randrange(4) << 4) + bytes(
            [self.rng.randrange(256), self.rng.randrange(256), 0, 0])
        return gsmtap_pkt(bbis(l3), gsmtap.CH_BCCH), {"name": "System Information Type 2"}

    def si3(self):
        mcc = self.rng.choice(["425", "208", "310", "001"])
        mnc = self.rng.choice(["01", "20", "410", "001"])
        lac, ci = self.rng.randrange(1, 65535), self.rng.randrange(65536)
        ccd = bytes([self.rng.randrange(256) & 0xFF, self.rng.randrange(8) | (self.rng.randrange(4) << 5),
                     self.rng.randrange(256)])
        l3 = (bytes([0x06, 0x1B]) + ci.to_bytes(2, "big") + lai_bytes(mcc, mnc, lac) + ccd
              + bytes([self.rng.randrange(128), self.rng.randrange(256), self.rng.randrange(256)])
              + bytes([self.rng.randrange(256), self.rng.randrange(256), self.rng.randrange(256)]))
        rest = self.rng.randbytes(4)
        exp = {"name": "System Information Type 3", "mcc": mcc, "mnc": mnc, "lac": lac, "cell_id": ci}
        return gsmtap_pkt(bbis(l3, rest), gsmtap.CH_BCCH), exp

    # --- SDCCH -----------------------------------------------------------------

    def lu_request(self):
        mi, e = self.identity(("imsi", "tmsi"))
        mcc, mnc, lac = "425", self.rng.choice(["01", "02", "410"]), self.rng.randrange(65535)
        l3 = bytes([0x05, 0x08, self.rng.randrange(256) & 0x7B]) + lai_bytes(mcc, mnc, lac) + b"\x57" + lv(mi)
        exp = {"name": "Location Updating Request", "identity": e,
               "old_lai": {"mcc": mcc, "mnc": mnc, "lac": lac}}
        return gsmtap_pkt(ua(l3), gsmtap.CH_SDCCH8, timeslot=1, sub_slot=self.rng.randrange(8)), exp

    def paging_response(self):
        mi, e = self.identity(("imsi", "tmsi", "imei"))
        l3 = bytes([0x06, 0x27, 0x07]) + lv(b"\x57\x18\x81") + lv(mi)
        return gsmtap_pkt(ua(l3), gsmtap.CH_SDCCH8, timeslot=1), {"name": "Paging Response", "identity": e}

    def cm_service_request(self):
        mi, e = self.identity(("imsi", "tmsi"))
        l3 = bytes([0x05, 0x24, 0x71]) + lv(b"\x57\x18\x81") + lv(mi)
        return gsmtap_pkt(ua(l3), gsmtap.CH_SDCCH8, timeslot=1), {"name": "CM Service Request", "identity": e}

    def lu_accept(self):
        t = self.tmsi()
        l3 = bytes([0x05, 0x02]) + lai_bytes("262", "01", 100) + b"\x17" + lv(mi_tmsi(t))
        return (gsmtap_pkt(iframe(l3), gsmtap.CH_SDCCH8, timeslot=1),
                {"name": "Location Updating Accept", "identity": {"kind": "tmsi", "value": t.hex().upper()}})

    def cipher_mode(self):
        algo = self.rng.randrange(7)
        sc = self.rng.random() < 0.8
        l3 = bytes([0x06, 0x35, (algo << 1) | int(sc)])
        exp_algo = f"A5/{algo + 1}" if sc else "A5/0"
        # N(S)=1: in generated streams this follows lu_accept (N(S)=0) on the same link.
        return (gsmtap_pkt(iframe(l3, ns=1), gsmtap.CH_SDCCH8, timeslot=1),
                {"name": "Ciphering Mode Command", "algorithm": exp_algo})
