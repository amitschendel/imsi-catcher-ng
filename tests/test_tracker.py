from imsicatcher import gsmtap
from imsicatcher.decoder import Decoder
from imsicatcher.plmn import PlmnDB
from imsicatcher.tracker import Tracker

import synth

DB = PlmnDB.load()


class Harness:
    def __init__(self):
        self.events = []
        self.t = Tracker(DB, on_event=self.events.append)
        self.dec = Decoder()
        self.ts = 1000.0

    def feed(self, dgram, dt=0.1):
        self.ts += dt
        self.t.process(self.ts, self.dec.decode(dgram))

    def of(self, kind):
        return [e for e in self.events if e["event"] == kind]


def si3(arfcn=61, mcc="262", mnc="01", lac=100, ci=2001, ccch_conf=0, neci=True):
    l3 = (bytes([0x06, 0x1B]) + ci.to_bytes(2, "big") + synth.lai_bytes(mcc, mnc, lac)
          + bytes([ccch_conf, 0x03, 0x00, 0x01, 0x00, 0x40 if neci else 0x00, 0x00, 0x00, 0x00]))
    return synth.gsmtap_pkt(synth.bbis(l3, b"\x2b" * 4), gsmtap.CH_BCCH, arfcn=arfcn)


def ia(arfcn=61, ts=1, sub=3, ta=4, ra=0x05):
    cd = bytes([(0b01000 | sub) << 3 | ts, arfcn >> 8, arfcn & 0xFF])
    l3 = bytes([0x06, 0x3F, 0x00]) + cd + bytes([ra, 0, 0, ta, 0])
    return synth.gsmtap_pkt(synth.bbis(l3), gsmtap.CH_CCCH, arfcn=arfcn)


def sdcch(frame, arfcn=61, ts=1, sub=3):
    return synth.gsmtap_pkt(frame, gsmtap.CH_SDCCH8, arfcn=arfcn, timeslot=ts, sub_slot=sub)


IMSI = "425019876543210"
TMSI = bytes.fromhex("1a2b3c4d")


def lu_request(identity):
    l3 = bytes([0x05, 0x08, 0x70]) + synth.lai_bytes("425", "02", 77) + b"\x57" + synth.lv(identity)
    return synth.ua(l3)


def lu_accept(new_tmsi):
    l3 = bytes([0x05, 0x02]) + synth.lai_bytes("262", "01", 100) + b"\x17" + synth.lv(synth.mi_tmsi(new_tmsi))
    return synth.iframe(l3)


def release(ns=1):
    return synth.iframe(bytes([0x06, 0x0D, 0x00]), ns=ns)


def test_cells_are_per_arfcn():
    h = Harness()
    h.feed(si3(arfcn=61, ci=2001))
    h.feed(si3(arfcn=64, mnc="02", ci=7))
    assert h.t.cells[61].cgi == "262-01-100-2001"
    assert h.t.cells[64].cgi == "262-02-100-7"
    assert h.t.cells[61].network.name == "Telekom"
    assert len(h.of("cell")) == 2


def test_session_links_imsi_to_new_tmsi_and_carries_ta():
    h = Harness()
    h.feed(si3())
    h.feed(ia(ta=4))
    h.feed(sdcch(lu_request(synth.mi_imsi(IMSI))))
    h.feed(sdcch(lu_accept(TMSI)))
    h.feed(sdcch(release()))
    sess = h.of("session")
    assert len(sess) == 1
    s = sess[0]
    assert s["procedure"] == "location update"
    assert s["identity"] == {"kind": "imsi", "value": IMSI}
    assert s["ta"] == 4 and s["distance_m"] == 2214
    assert s["cause"] == "location updating"
    assert s["old_lai"]["mnc"] == "02"
    links = h.of("link")
    assert len(links) == 1 and links[0]["b"]["value"] == "1A2B3C4D"
    assert ("tmsi", "1A2B3C4D") in h.t.identities[("imsi", IMSI)].links


def test_paging_identity_counts():
    h = Harness()
    h.feed(si3())
    l3 = bytes([0x06, 0x21, 0x00]) + synth.lv(synth.mi_tmsi(TMSI))
    for _ in range(3):
        h.feed(synth.gsmtap_pkt(synth.bbis(l3), gsmtap.CH_CCCH))
    rec = h.t.identities[("tmsi", "1A2B3C4D")]
    assert rec.count == 3 and rec.sources["paging"] == 3
    assert len(h.of("identity")) == 1 and len(h.of("paging")) == 3


def test_sdcch4_ignored_on_non_combined_cell():
    h = Harness()
    h.feed(si3(ccch_conf=0))
    frame = synth.gsmtap_pkt(lu_request(synth.mi_imsi(IMSI)), gsmtap.CH_SDCCH4)
    h.feed(frame)
    assert ("imsi", IMSI) not in h.t.identities
    h2 = Harness()
    h2.feed(si3(ccch_conf=1))
    h2.feed(frame)
    assert ("imsi", IMSI) in h2.t.identities


def test_reject_event_and_roaming_flag():
    h = Harness()
    h.feed(si3())
    roamer = "724031234567890"
    h.feed(sdcch(lu_request(synth.mi_imsi(roamer))))
    h.feed(sdcch(synth.iframe(bytes([0x05, 0x04, 0x0D]))))
    rej = h.of("reject")
    assert rej and rej[0]["cause"] == "roaming not allowed in this location area"
    new = [e for e in h.of("identity") if e["kind"] == "imsi"][0]
    assert new["foreign"] is True and new["country"] == "Brazil"


def test_split_imsi_mnc_length():
    assert DB.split_imsi("310410123456789") == ("310", "410", "123456789")
    assert DB.split_imsi("425011234567890") == ("425", "01", "1234567890")
    # The serving cell's MNC length wins when the PLMN matches.
    assert DB.split_imsi("425011234567890", ("425", "011")) == ("425", "011", "234567890")


def test_stale_tmsis_are_pruned():
    h = Harness()
    h.feed(si3())
    l3 = bytes([0x06, 0x21, 0x00]) + synth.lv(synth.mi_tmsi(TMSI))
    h.feed(synth.gsmtap_pkt(synth.bbis(l3), gsmtap.CH_CCCH))
    h.t.dirty.clear()
    h.t.housekeeping(h.ts + 7200)
    assert ("tmsi", "1A2B3C4D") not in h.t.identities
    assert h.t.totals["unique:tmsi"] == 1


def test_sapi3_disc_does_not_split_session():
    h = Harness()
    h.feed(si3())
    h.feed(ia(ta=4))
    h.feed(sdcch(lu_request(synth.mi_imsi(IMSI))))
    h.feed(sdcch(synth.lapdm(b"", ctrl=0x53, sapi=3)))  # DISC on SAPI 3
    h.feed(sdcch(lu_accept(TMSI)))
    h.feed(sdcch(release()))
    assert len(h.of("session")) == 1 and len(h.of("link")) == 1


def test_repeated_ua_keeps_one_session():
    h = Harness()
    h.feed(si3())
    h.feed(ia(ta=4))
    h.feed(sdcch(lu_request(synth.mi_imsi(IMSI))))
    h.feed(sdcch(lu_request(synth.mi_imsi(IMSI))))
    h.feed(sdcch(lu_accept(TMSI)))
    h.feed(sdcch(release()))
    sess = h.of("session")
    assert len(sess) == 1 and sess[0]["ta"] == 4 and len(h.of("link")) == 1


def test_assignment_on_other_carrier_not_matched():
    h = Harness()
    h.feed(si3())
    cd = bytes([(0b01000 | 3) << 3 | 1, 0, 30])  # SDCCH/8 sub 3 TS1 on ARFCN 30
    l3 = bytes([0x06, 0x3F, 0x00]) + cd + bytes([0x05, 0, 0, 40, 0])
    h.feed(synth.gsmtap_pkt(synth.bbis(l3), gsmtap.CH_CCCH))
    h.feed(sdcch(lu_request(synth.mi_imsi(IMSI))))
    h.feed(sdcch(release(ns=0)))
    s = h.of("session")[0]
    assert s["ta"] is None and s["cause"] is None
    assert h.of("assignment")[0]["observable"] is False
