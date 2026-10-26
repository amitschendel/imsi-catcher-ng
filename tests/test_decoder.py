import zlib

import pytest

from imsicatcher import gsmtap, ie
from imsicatcher.decoder import Decoder
from imsicatcher.lapdm import Reassembler, parse_frame

import synth
from synth import Gen


def decode_one(dgram):
    d = Decoder().decode(dgram)
    assert d is not None
    assert len(d.messages) == 1, d
    return d.messages[0]


def subset(expected, actual):
    """Every key in `expected` matches `actual` (recursively)."""
    if isinstance(expected, dict):
        assert isinstance(actual, dict), actual
        for k, v in expected.items():
            assert k in actual, (k, actual)
            subset(v, actual[k])
    elif isinstance(expected, list):
        assert len(expected) == len(actual), (expected, actual)
        for e, a in zip(expected, actual):
            subset(e, a)
    else:
        assert expected == actual


BUILDERS = ["paging1", "paging2", "paging3", "ia", "iax", "iar", "si3", "lu_request",
            "paging_response", "cm_service_request", "lu_accept", "cipher_mode"]


@pytest.mark.parametrize("builder", BUILDERS)
def test_roundtrip(builder):
    g = Gen(seed=zlib.crc32(builder.encode()))
    for _ in range(300):
        dgram, expected = getattr(g, builder)()
        msg = decode_one(dgram)
        assert "error" not in msg, msg
        subset(expected, msg)


def test_gsmtap_header():
    h = bytes.fromhex("02040100003dda00000af7d6020000002b")
    hdr, payload = gsmtap.parse_header(h)
    assert hdr.arfcn == 61 and hdr.signal_dbm == -38 and hdr.channel == gsmtap.CH_CCCH
    assert hdr.frame_number == 0x0AF7D6 and bytes(payload) == b"\x2b"


def test_gsmtap_signed_signal_and_flags():
    raw = gsmtap.build_header(512, gsmtap.CH_SDCCH8, signal_dbm=-100, uplink=True, pcs=True, acch=True)
    hdr, _ = gsmtap.parse_header(raw)
    assert (hdr.arfcn, hdr.signal_dbm, hdr.uplink, hdr.pcs, hdr.acch) == (512, -100, True, True, True)


def test_gsmtap_rejects_garbage():
    assert Decoder().decode(b"\x00" * 8) is None
    assert Decoder().decode(b"\x07" + b"\x00" * 20) is None


def test_mobile_identity_even_imsi():
    v = synth.mi_imsi("42501123456789")  # 14 digits, even
    assert ie.mobile_identity(v) == {"kind": "imsi", "value": "42501123456789"}


def test_mobile_identity_imeisv_and_imei_luhn():
    assert ie.mobile_identity(synth.encode_digits(3, "3520990017614823"))["kind"] == "imeisv"
    good = Gen(3).imei()
    assert ie.mobile_identity(synth.mi_imei(good))["luhn_ok"] is True


def test_mobile_identity_rejects_imeisv_type_as_imsi():
    # The original tool tested only bit 0 of the type field, so IMEISV (011) passed as IMSI (001).
    v = synth.encode_digits(3, "3520990017614823")
    assert ie.mobile_identity(v)["kind"] != "imsi"


def test_mobile_identity_errors():
    with pytest.raises(ie.IEError):
        ie.mobile_identity(b"\xf4\x01\x02")  # short TMSI
    with pytest.raises(ie.IEError):
        ie.mobile_identity(bytes([0x19, 0xA2]))  # non-decimal digit


def test_lai_three_digit_mnc():
    assert ie.lai(synth.lai_bytes("310", "410", 1234)) == {"mcc": "310", "mnc": "410", "lac": 1234}
    assert ie.lai(synth.lai_bytes("262", "01", 100)) == {"mcc": "262", "mnc": "01", "lac": 100}


def test_lai_deleted():
    assert ie.lai(bytes.fromhex("fffffffffe"))["deleted"] is True


def test_frequency_list_bitmap0():
    v = bytearray(16)
    v[15] = 0x01  # ARFCN 1
    v[0] = 0x08  # ARFCN 124
    v[14] = 0x80  # ARFCN 16
    assert ie.frequency_list(bytes(v)) == [1, 16, 124]


def test_frequency_list_1024_single():
    # F0 clear, W(1) = 61, rest zero: just ARFCN 61.
    w1 = 61
    v = bytes([0x80 | (w1 >> 8), w1 & 0xFF]) + bytes(14)
    assert ie.frequency_list(v) == [61]


def test_frequency_list_variable_bitmap():
    orig = 100
    v = bytearray(16)
    v[0] = 0x8E | (orig >> 9)
    v[1] = (orig >> 1) & 0xFF
    v[2] = ((orig & 1) << 7) | 0x40  # RRFCN 1 -> ARFCN 101
    assert ie.frequency_list(bytes(v)) == [100, 101]


def test_request_reference_frame_number():
    ref = ie.request_reference(bytes([0x23, (5 << 3) | (40 >> 3), ((40 & 7) << 5) | 12]))
    assert (ref["ra"], ref["t1"], ref["t3"], ref["t2"]) == (0x23, 5, 40, 12)
    assert ref["fn_mod_42432"] % 51 == 40 and ref["fn_mod_42432"] % 26 == 12


def test_establishment_cause():
    assert ie.establishment_cause(0xA5) == "emergency call"
    assert ie.establishment_cause(0x80).startswith("answer to paging")
    assert ie.establishment_cause(0x05) == "location updating"
    assert ie.establishment_cause(0x15, neci=True) == "answer to paging (SDCCH) or other SDCCH procedure"
    assert ie.establishment_cause(0x15, neci=False) == "location updating or answer to paging (SDCCH)"
    assert ie.establishment_cause(0x20) == "answer to paging (TCH/F)"
    assert ie.establishment_cause(0x30) == "answer to paging (TCH/H or TCH/F)"


def test_si13_and_si2quater_pseudo_length():
    si13 = synth.bbis(bytes([0x06, 0x00]), bytes.fromhex("90"), pseudo_len=0)
    msg = decode_one(synth.gsmtap_pkt(si13, gsmtap.CH_CCCH))
    assert msg["name"] == "System Information Type 13"


def test_paging1_mi2_only_within_pseudo_length():
    # Bytes after the pseudo length are rest octets even if they look like an IEI 0x17.
    l3 = bytes([0x06, 0x21, 0x00]) + synth.lv(synth.mi_tmsi(b"\x01\x02\x03\x04"))
    payload = synth.bbis(l3, rest=b"\x17\x05\xf4\xaa\xbb\xcc\xdd")
    msg = decode_one(synth.gsmtap_pkt(payload, gsmtap.CH_CCCH))
    assert [i["value"] for i in msg["identities"]] == ["01020304"]


def test_mm_message_type_ignores_send_sequence_bits():
    l3 = bytes([0x05, 0x08 | 0x40, 0x70]) + synth.lai_bytes("425", "01", 1) + b"\x57" + synth.lv(
        synth.mi_tmsi(b"\xde\xad\xbe\xef"))
    msg = decode_one(synth.gsmtap_pkt(synth.ua(l3), gsmtap.CH_SDCCH8))
    assert msg["name"] == "Location Updating Request"


def test_lapdm_reassembly():
    l3 = bytes([0x05, 0x32, 0x43, 0x08, 0x80]) + b"P" * 30
    r = Reassembler()
    link = ("x",)
    r.reset(link)
    assert r.push(link, parse_frame(synth.iframe(l3[:20], ns=0, more=True))) is None
    assert r.push(link, parse_frame(synth.iframe(l3[20:], ns=1))) == l3


def test_lapdm_retransmissions_and_gaps():
    r = Reassembler()
    link = ("x",)
    r.reset(link)
    a = parse_frame(synth.iframe(b"A" * 20, ns=0, more=True))
    b = parse_frame(synth.iframe(b"B" * 20, ns=1, more=True))
    c = parse_frame(synth.iframe(b"C" * 4, ns=2))
    assert r.push(link, a) is None
    assert r.push(link, b) is None
    assert r.push(link, b) is None  # retransmitted middle segment is ignored
    assert r.push(link, c) == b"A" * 20 + b"B" * 20 + b"C" * 4
    single = parse_frame(synth.iframe(b"\x06\x35\x03", ns=3))
    assert r.push(link, single) == b"\x06\x35\x03"
    assert r.push(link, single) is None  # delivered once
    # Lost first segment: the tail must not be decoded as a message.
    r.reset(link)
    assert r.push(link, parse_frame(synth.iframe(b"B" * 20, ns=1, more=True))) is None
    assert r.push(link, parse_frame(synth.iframe(b"C" * 4, ns=2))) is None
    assert r.push(link, parse_frame(synth.iframe(b"D" * 4, ns=3))) == b"D" * 4


def test_lapdm_unsynced_link_skips_partial_message():
    r = Reassembler()
    link = ("y",)
    assert r.push(link, parse_frame(synth.iframe(b"B" * 20, ns=4, more=True))) is None
    assert r.push(link, parse_frame(synth.iframe(b"C" * 4, ns=5))) is None
    assert r.push(link, parse_frame(synth.iframe(b"E" * 4, ns=6))) == b"E" * 4


def test_assignment_command_channel_description_2():
    msg = decode_one(synth.gsmtap_pkt(synth.iframe(bytes.fromhex("062e00203d00")), gsmtap.CH_SDCCH8))
    assert msg["channel"]["channel"] == "TCH/F (SACCH/M)"


def test_gsm7_extension_table():
    from imsicatcher.mm import gsm7_unpack
    packed, spare = gsm7_pack("A\x1b(B")
    assert gsm7_unpack(packed, spare) == "A{B"


def test_invalid_lapdm_on_sdcch4_rejected():
    # A CCCH block demapped as SDCCH/4 by a receiver that assumed a combined config.
    paging = synth.bbis(bytes([0x06, 0x21, 0x00, 0x01, 0xF0]))
    d = Decoder().decode(synth.gsmtap_pkt(paging, gsmtap.CH_SDCCH4))
    assert d.messages == [] and d.error


def test_sacch_short_pd_and_si6():
    si6 = bytes([0x06, 0x1E, 0x07, 0xD1]) + synth.lai_bytes("262", "01", 100) + b"\x94\xff"
    payload = b"\x05\x02" + synth.lapdm(si6, ctrl=0x03, size=21)
    d = Decoder().decode(synth.gsmtap_pkt(payload, gsmtap.CH_SDCCH8, acch=True))
    assert d.sacch["ta"] == 2
    assert d.messages[0]["cell_id"] == 2001 and d.messages[0]["lac"] == 100
    short = b"\x05\x02" + bytes([0x05 << 2]) + b"\x2b" * 20
    d = Decoder().decode(synth.gsmtap_pkt(short, gsmtap.CH_SDCCH8, acch=True))
    assert d.messages[0]["name"] == "Measurement Information"


def gsm7_pack(text: str) -> tuple[bytes, int]:
    bits = 0
    nbits = 0
    out = bytearray()
    for ch in text:
        bits |= (ord(ch) & 0x7F) << nbits  # ASCII letters map 1:1 in the GSM default alphabet
        nbits += 7
        while nbits >= 8:
            out.append(bits & 0xFF)
            bits >>= 8
            nbits -= 8
    spare = 0
    if nbits:
        out.append(bits & 0xFF)
        spare = 8 - nbits
    return bytes(out), spare


def test_mm_information_network_name_and_time():
    packed, spare = gsm7_pack("PARTNER")
    name = bytes([0x80 | spare]) + packed
    # 2026-10-25 20:23:43 UTC, local offset +8 quarter hours, swapped-nibble BCD.
    t = bytes.fromhex("620152023234") + bytes([0x80])
    l3 = bytes([0x05, 0x32, 0x43, len(name)]) + name + b"\x47" + t
    msg = decode_one(synth.gsmtap_pkt(synth.iframe(l3), gsmtap.CH_SDCCH8))
    assert msg["network_full_name"] == "PARTNER"
    assert msg["network_time_utc"] == "2026-10-25T20:23:43+00:00"
    assert msg["utc_offset_minutes"] == 120


class BitWriter:
    def __init__(self):
        self.bits = []

    def put(self, value, n):
        self.bits += [(value >> (n - 1 - i)) & 1 for i in range(n)]
        return self

    def to_bytes(self, size):
        b = self.bits + [0] * (size * 8 - len(self.bits))
        return bytes(int("".join(map(str, b[i:i + 8])), 2) for i in range(0, size * 8, 8))


def test_si2quater_utran_fdd_neighbours():
    w = BitWriter()
    w.put(1, 1).put(0, 1).put(0, 1).put(0, 4).put(0, 4)  # BA_IND, 3G_BA_IND, MP, index, count
    w.put(0, 6)  # no measurement, RTD, BSIC, priority, GPRS measurement, NC parameters
    w.put(1, 1).put(4, 8).put(0, 5)  # extension information: length 4 means 5 bits
    w.put(1, 1).put(0, 1).put(0, 1)  # 3G description, no index start, no EMR index
    w.put(1, 1).put(0, 1)  # UTRAN FDD description, no bandwidth
    w.put(1, 1).put(0, 1).put(10700, 14).put(0, 1).put(3, 5).put(0, 28)  # UARFCN 10700, 3 cells
    w.put(1, 1).put(0, 1).put(2950, 14).put(0, 1).put(1, 5).put(0, 10)  # UARFCN 2950, 1 cell
    w.put(0, 1)  # end of repeated cells
    w.put(0, 1)  # no TDD
    payload = synth.bbis(bytes([0x06, 0x07]), w.to_bytes(20), pseudo_len=1)
    msg = decode_one(synth.gsmtap_pkt(payload, gsmtap.CH_CCCH))
    assert msg["utran_fdd"] == [{"uarfcn": 10700, "cells": 3}, {"uarfcn": 2950, "cells": 1}]


def test_arfcn_frequencies():
    from imsicatcher import arfcn
    assert arfcn.downlink_mhz(61) == 947.2
    assert arfcn.downlink_mhz(0) == 935.0
    assert arfcn.downlink_mhz(1023) == 934.8
    assert arfcn.downlink_mhz(512) == 1805.2
    assert arfcn.downlink_mhz(512, pcs=True) == 1930.2
    assert arfcn.downlink_mhz(128) == 869.2
    assert arfcn.arfcn_from_downlink(947.2) == 61
    assert arfcn.band_of(975) == "E-GSM900"
    assert arfcn.uarfcn_info(10662) == ("B1", 2132.4)
    assert arfcn.uarfcn_info(3011) == ("B8", 942.2)
    assert arfcn.parse_frequency("947.2M") == 947.2e6
    assert arfcn.parse_frequency("1842.6") == 1842.6e6


def test_parse_grgsm_scanner_output():
    from imsicatcher.radio import parse_scan_output
    text = ("Scanning: 20.00% done..\n"
            "ARFCN:   17, Freq:  938.4M, CID:  2001, LAC:   100, MCC:   1, MNC:   1, Pwr: -41\n"
            "  |---- Configuration: 1 CCCH, not combined\n"
            "  |---- Cell ARFCNs: 17, 30\n"
            "  |---- Neighbour Cells: 20, 25\n")
    (r,) = parse_scan_output(text)
    assert (r.arfcn, r.cid, r.lac, r.mcc, r.mnc, r.power_db) == (17, 2001, 100, 1, 1, -41)
    assert r.cell_arfcns == [17, 30] and r.neighbours == [20, 25]


def test_stall_watch(monkeypatch):
    from imsicatcher import radio
    cpu = {"v": 10.0}
    clock = {"t": 0.0}
    monkeypatch.setattr(radio, "cpu_seconds", lambda pid: cpu["v"])
    monkeypatch.setattr(radio.time, "monotonic", lambda: clock["t"])
    w = radio.StallWatch(123, limit=90)
    clock["t"] = 60
    cpu["v"] = 15.0
    assert not w.stalled()  # still working
    clock["t"] = 140
    assert not w.stalled()  # idle for 80 s only
    clock["t"] = 160
    assert w.stalled()


def test_cpu_seconds_on_linux():
    import os
    import sys
    from imsicatcher.radio import cpu_seconds
    v = cpu_seconds(os.getpid())
    assert (v is None) if not sys.platform.startswith("linux") else v >= 0
