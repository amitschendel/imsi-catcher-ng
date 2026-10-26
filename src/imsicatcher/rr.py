"""Radio Resource management messages (3GPP TS 44.018)."""

from __future__ import annotations

from .bits import BitReader, BitsExhausted
from . import ie
from .ie import IEError

MSG_NAMES = {
    0x00: "System Information Type 13",
    0x02: "System Information Type 2bis",
    0x03: "System Information Type 2ter",
    0x04: "System Information Type 9",
    0x05: "System Information Type 5bis",
    0x06: "System Information Type 5ter",
    0x07: "System Information Type 2quater",
    0x0A: "Partial Release",
    0x0D: "Channel Release",
    0x0F: "Partial Release Complete",
    0x10: "Channel Mode Modify",
    0x12: "RR Status",
    0x13: "Classmark Enquiry",
    0x14: "Frequency Redefinition",
    0x15: "Measurement Report",
    0x16: "Classmark Change",
    0x17: "Channel Mode Modify Acknowledge",
    0x18: "System Information Type 8",
    0x19: "System Information Type 1",
    0x1A: "System Information Type 2",
    0x1B: "System Information Type 3",
    0x1C: "System Information Type 4",
    0x1D: "System Information Type 5",
    0x1E: "System Information Type 6",
    0x1F: "System Information Type 7",
    0x20: "Notification/NCH",
    0x21: "Paging Request Type 1",
    0x22: "Paging Request Type 2",
    0x24: "Paging Request Type 3",
    0x27: "Paging Response",
    0x28: "Handover Failure",
    0x29: "Assignment Complete",
    0x2B: "Handover Command",
    0x2C: "Handover Complete",
    0x2D: "Physical Information",
    0x2E: "Assignment Command",
    0x2F: "Assignment Failure",
    0x32: "Ciphering Mode Complete",
    0x35: "Ciphering Mode Command",
    0x36: "Extended Measurement Order",
    0x37: "Extended Measurement Report",
    0x38: "Application Information",
    0x39: "Immediate Assignment Extended",
    0x3A: "Immediate Assignment Reject",
    0x3B: "Additional Assignment",
    0x3D: "System Information Type 16",
    0x3E: "System Information Type 17",
    0x3F: "Immediate Assignment",
    0x40: "System Information Type 14",
    0x41: "System Information Type 13alt",
    0x42: "System Information Type 15",
    0x43: "System Information Type 18",
    0x44: "System Information Type 19",
    0x45: "System Information Type 20",
    0x46: "System Information Type 21",
}

PAGE_MODES = ("normal", "extended", "reorganization", "same as before")
CHANNEL_NEEDED = ("any", "SDCCH", "TCH/F", "TCH/H or TCH/F")
CCCH_CONF = {
    0: "1 basic physical channel, not combined",
    1: "1 basic physical channel, combined with SDCCH/4",
    2: "2 basic physical channels, not combined",
    4: "3 basic physical channels, not combined",
    6: "4 basic physical channels, not combined",
}
TX_INTEGER = (3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 16, 20, 25, 32, 50)
MAX_RETRANS = (1, 2, 4, 7)
CIPHER_ALGOS = ("A5/1", "A5/2", "A5/3", "A5/4", "A5/5", "A5/6", "A5/7", "reserved")
RR_CAUSES = {
    0x00: "normal event",
    0x01: "abnormal release, unspecified",
    0x02: "abnormal release, channel unacceptable",
    0x03: "abnormal release, timer expired",
    0x04: "abnormal release, no activity on the radio path",
    0x05: "preemptive release",
    0x06: "UTRAN configuration unknown",
    0x08: "handover impossible, timing advance out of range",
    0x09: "channel mode unacceptable",
    0x0A: "frequency not implemented",
    0x0B: "originator or talker leaving group call area",
    0x0C: "lower layer failure",
    0x41: "call already cleared",
    0x5F: "semantically incorrect message",
    0x60: "invalid mandatory information",
    0x61: "message type non-existent or not implemented",
    0x62: "message type not compatible with protocol state",
    0x64: "conditional IE error",
    0x65: "no cell allocation available",
    0x6F: "protocol error unspecified",
}
NMO = ("I", "II", "III", "reserved")
T3192_MS = (500, 1000, 1500, 0, 80, 120, 160, 200)


def _need(v, n: int) -> None:
    if len(v) < n:
        raise IEError("message truncated")


# --- shared IEs ---------------------------------------------------------------

def rach_control(v: bytes) -> dict:
    _need(v, 3)
    barred = [c for c in range(16) if (((v[1] << 8) | v[2]) >> c) & 1 and c != 10]
    return {
        "max_retrans": MAX_RETRANS[v[0] >> 6],
        "tx_integer": TX_INTEGER[(v[0] >> 2) & 0x0F],
        "cell_barred": bool(v[0] & 0x02),
        "call_reestablishment_allowed": not v[0] & 0x01,
        "emergency_call_restricted": bool(v[1] & 0x04),
        "barred_access_classes": barred,
    }


def cell_selection(v: bytes) -> dict:
    _need(v, 2)
    return {
        "cell_reselect_hysteresis_db": (v[0] >> 5) * 2,
        "ms_txpwr_max_cch": v[0] & 0x1F,
        "acs": bool(v[1] & 0x80),
        "neci": bool(v[1] & 0x40),
        "rxlev_access_min_dbm": -110 + (v[1] & 0x3F),
    }


def control_channel_description(v: bytes) -> dict:
    _need(v, 3)
    conf = v[0] & 0x07
    return {
        "mscr": v[0] >> 7,
        "att": bool(v[0] & 0x40),
        "bs_ag_blks_res": (v[0] >> 3) & 0x07,
        "ccch_conf": conf,
        "ccch_conf_text": CCCH_CONF.get(conf, "reserved"),
        "combined_sdcch4": conf == 1,
        "cbq3": (v[1] >> 5) & 0x03,
        "bs_pa_mfrms": (v[1] & 0x07) + 2,
        "t3212_minutes": v[2] * 6,
    }


def cell_options_bcch(b: int) -> dict:
    return {
        "pwrc": bool(b & 0x40),
        "dtx": (b >> 4) & 0x03,
        "radio_link_timeout": ((b & 0x0F) + 1) * 4,
    }


# --- rest octets ---------------------------------------------------------------

def si1_rest(rest: bytes) -> dict:
    out = {}
    r = BitReader(rest)
    try:
        if r.lh():
            out["nch_position"] = r.bits(5)
        out["band_indicator"] = "PCS1900" if r.lh() else "DCS1800"
    except BitsExhausted:
        pass
    return out


def _optional_selection(r: BitReader, out: dict) -> None:
    if r.lh():
        out["cbq"] = r.bit()
        out["cell_reselect_offset_db"] = r.bits(6) * 2
        t = r.bits(3)
        out["temporary_offset_db"] = None if t == 7 else t * 10  # 7 means infinity
        p = r.bits(5)
        # 31 means "subtract CELL_RESELECT_OFFSET, ignore TEMPORARY_OFFSET".
        out["penalty_time_s"] = None if p == 31 else p * 20 + 20


def si3_rest(rest: bytes) -> dict:
    out: dict = {}
    r = BitReader(rest)
    try:
        _optional_selection(r, out)
        if r.lh():
            out["power_offset_db"] = r.bits(2) * 2
        out["si2ter_present"] = bool(r.lh())
        out["early_classmark_sending"] = bool(r.lh())
        if r.lh():
            out["scheduling_where"] = r.bits(3)
        if r.lh():
            out["gprs"] = {"ra_colour": r.bits(3), "si13_position": "extended" if r.bit() else "normal"}
        else:
            out["gprs"] = None
        out["3g_early_classmark_restriction"] = bool(r.lh())
        if r.lh():
            out["si2quater_position"] = "extended" if r.bit() else "normal"
        else:
            out["si2quater_position"] = None
    except BitsExhausted:
        pass
    return out


def si4_rest(rest: bytes) -> dict:
    out: dict = {}
    r = BitReader(rest)
    try:
        _optional_selection(r, out)
        if r.lh():
            out["power_offset_db"] = r.bits(2) * 2
        if r.lh():
            out["gprs"] = {"ra_colour": r.bits(3), "si13_position": "extended" if r.bit() else "normal"}
        else:
            out["gprs"] = None
    except BitsExhausted:
        pass
    return out


def _gprs_mobile_allocation(r: BitReader) -> None:
    r.bits(6)  # HSN
    while r.bit():
        r.bits(4)  # RFL_NUMBER
    if r.bit():
        while r.bit():
            r.bits(6)  # ARFCN_INDEX
    else:
        r.bits(r.bits(6) + 1)  # MA_BITMAP


def si13_rest(rest: bytes) -> dict:
    out: dict = {}
    r = BitReader(rest)
    try:
        if not r.lh():
            return out
        out["bcch_change_mark"] = r.bits(3)
        out["si_change_field"] = r.bits(4)
        if r.bit():
            out["si13_change_mark"] = r.bits(2)
            _gprs_mobile_allocation(r)
        if r.bit():
            out["pbcch"] = True
            return out
        out["rac"] = r.bits(8)
        out["spgc_ccch_sup"] = bool(r.bit())
        out["priority_access_thr"] = r.bits(3)
        out["network_control_order"] = r.bits(2)
        nmo = r.bits(2)
        opts = {
            "nmo": NMO[nmo],
            "t3168_ms": (r.bits(3) + 1) * 500,
            "t3192_ms": T3192_MS[r.bits(3)],
            "drx_timer_max": r.bits(3),
            "access_burst_type": "11 bit" if r.bit() else "8 bit",
            "control_ack_type": "RLC/MAC block" if r.bit() else "access bursts",
            "bs_cv_max": r.bits(4),
        }
        if r.bit():
            r.bits(9)  # PAN_DEC, PAN_INC, PAN_MAX
        if r.bit():
            ext_len = r.bits(6) + 1
            end = r.pos + ext_len
            ext = BitReader(r.data, r.pos, min(end, r.end))
            try:
                if ext.bit():
                    opts["egprs"] = True
                    opts["egprs_packet_channel_request"] = bool(ext.bit())
                    opts["bep_period"] = ext.bits(4)
                else:
                    opts["egprs"] = False
                opts["pfc_feature_mode"] = bool(ext.bit())
                opts["dtm_support"] = bool(ext.bit())
                opts["bss_paging_coordination"] = bool(ext.bit())
            except BitsExhausted:
                pass  # shorter extension from an older release
            r.pos = end
        else:
            opts["egprs"] = False
        out["gprs_cell_options"] = opts
    except BitsExhausted:
        pass
    return out


def p1_rest(rest: bytes) -> dict:
    out: dict = {}
    r = BitReader(rest)
    try:
        if r.lh():
            r.bits(3)  # NLN(PCH), NLN status
        if r.lh():
            out["priority1"] = r.bits(3)
        if r.lh():
            out["priority2"] = r.bits(3)
        if r.lh():
            out["group_call_info"] = True
            return out
        out["packet_page_1"] = bool(r.lh())
        out["packet_page_2"] = bool(r.lh())
    except BitsExhausted:
        pass
    return out


def p2_rest(rest: bytes) -> dict:
    out: dict = {}
    r = BitReader(rest)
    try:
        if r.lh():
            out["channel_needed_3"] = CHANNEL_NEEDED[r.bits(2)]
        if r.lh():
            r.bits(3)
        for k in ("priority1", "priority2", "priority3"):
            if r.lh():
                out[k] = r.bits(3)
        out["packet_page_3"] = bool(r.lh())
    except BitsExhausted:
        pass
    return out


def p3_rest(rest: bytes) -> dict:
    out: dict = {}
    r = BitReader(rest)
    try:
        if r.lh():
            out["channel_needed_3"] = CHANNEL_NEEDED[r.bits(2)]
            out["channel_needed_4"] = CHANNEL_NEEDED[r.bits(2)]
    except BitsExhausted:
        pass
    return out


# --- CCCH / BCCH messages --------------------------------------------------------

def _page_header(b: int) -> dict:
    return {
        "page_mode": PAGE_MODES[b & 0x03],
        "channel_needed": [CHANNEL_NEEDED[(b >> 4) & 0x03], CHANNEL_NEEDED[(b >> 6) & 0x03]],
    }


def _optional_mi(body: bytes, off: int, out_ids: list) -> int:
    """Parse an optional Mobile Identity TLV with IEI 0x17 at `off`."""
    if off + 2 <= len(body) and body[off] == 0x17:
        n = body[off + 1]
        _need(body, off + 2 + n)
        out_ids.append(ie.mobile_identity(body[off + 2:off + 2 + n]))
        return off + 2 + n
    return off


def paging_1(body: bytes, rest: bytes) -> dict:
    _need(body, 4)
    out = _page_header(body[2])
    n = body[3]
    _need(body, 4 + n)
    ids = [ie.mobile_identity(body[4:4 + n])]
    _optional_mi(body, 4 + n, ids)
    out["identities"] = [i for i in ids if i["kind"] != ie.ID_NONE]
    out.update(p1_rest(rest))
    return out


def _tmsi(v: bytes) -> dict:
    return {"kind": ie.ID_TMSI, "value": v.hex().upper()}


def paging_2(body: bytes, rest: bytes) -> dict:
    _need(body, 11)
    out = _page_header(body[2])
    ids = [_tmsi(body[3:7]), _tmsi(body[7:11])]
    _optional_mi(body, 11, ids)
    out["identities"] = [i for i in ids if i["kind"] != ie.ID_NONE]
    out.update(p2_rest(rest))
    return out


def paging_3(body: bytes, rest: bytes) -> dict:
    _need(body, 19)
    out = _page_header(body[2])
    out["identities"] = [_tmsi(body[i:i + 4]) for i in (3, 7, 11, 15)]
    out.update(p3_rest(rest))
    return out


def _dedicated_or_tbf(b: int) -> dict:
    td = (b >> 4) & 0x0F
    return {"tbf": bool(td & 0x01), "downlink": bool(td & 0x02), "two_message": bool(td & 0x04)}


def immediate_assignment(body: bytes, rest: bytes) -> dict:
    _need(body, 11)
    out = {"page_mode": PAGE_MODES[body[2] & 0x03]}
    out.update(_dedicated_or_tbf(body[2]))
    desc = body[3:6]
    out["channel"] = ie.packet_channel_description(desc) if out["tbf"] else ie.channel_description(desc)
    out["request_reference"] = ie.request_reference(body[6:9])
    out.update(ie.timing_advance(body[9]))
    ma_len = body[10]
    _need(body, 11 + ma_len)
    out["mobile_allocation_len"] = ma_len
    off = 11 + ma_len
    if off + 3 <= len(body) and body[off] == 0x7C:
        out["starting_time"] = body[off + 1:off + 3].hex()
    return out


def immediate_assignment_ext(body: bytes, rest: bytes) -> dict:
    # chan1(3) ref1(3) ta1(1) chan2(3) ref2(3) ta2(1) mobile allocation (LV)
    _need(body, 18)
    out = {"page_mode": PAGE_MODES[body[2] & 0x03], "assignments": []}
    for c, r, t in ((3, 6, 9), (10, 13, 16)):
        a = {"channel": ie.channel_description(body[c:c + 3]),
             "request_reference": ie.request_reference(body[r:r + 3])}
        a.update(ie.timing_advance(body[t]))
        out["assignments"].append(a)
    return out


def immediate_assignment_reject(body: bytes, rest: bytes) -> dict:
    _need(body, 19)
    out = {"page_mode": PAGE_MODES[body[2] & 0x03], "rejects": []}
    for off in (3, 7, 11, 15):
        ref = ie.request_reference(body[off:off + 3])
        ref["wait_indication_s"] = body[off + 3]
        out["rejects"].append(ref)
    return out


def si1(body: bytes, rest: bytes) -> dict:
    _need(body, 21)
    out = {"cell_arfcns": ie.frequency_list(body[2:18]), "rach": rach_control(body[18:21])}
    out.update(si1_rest(rest))
    return out


def _neighbours(v: bytes) -> dict:
    return {
        "neighbours": ie.frequency_list(v),
        "ext_ind": bool(v[0] & 0x20),
        "ba_ind": (v[0] >> 4) & 0x01,
    }


def si2(body: bytes, rest: bytes) -> dict:
    _need(body, 22)
    out = _neighbours(body[2:18])
    out["ncc_permitted"] = [n for n in range(8) if body[18] >> n & 1]
    out["rach"] = rach_control(body[19:22])
    return out


def si2bis(body: bytes, rest: bytes) -> dict:
    _need(body, 21)
    out = _neighbours(body[2:18])
    out["rach"] = rach_control(body[18:21])
    return out


def si2ter(body: bytes, rest: bytes) -> dict:
    _need(body, 18)
    v = body[2:18]
    # Bits 7..5 of the first octet carry multiband reporting and BA-IND, not format bits.
    masked = bytes([v[0] & 0x8F]) + v[1:]
    return {"neighbours": ie.frequency_list(masked), "multiband_reporting": (v[0] >> 5) & 0x03}


def si3(body: bytes, rest: bytes) -> dict:
    _need(body, 18)
    out = {"cell_id": (body[2] << 8) | body[3]}
    out.update(ie.lai(body[4:9]))
    out["control_channel"] = control_channel_description(body[9:12])
    out["cell_options"] = cell_options_bcch(body[12])
    out["cell_selection"] = cell_selection(body[13:15])
    out["rach"] = rach_control(body[15:18])
    out.update(si3_rest(rest))
    return out


def si4(body: bytes, rest: bytes) -> dict:
    _need(body, 12)
    out = ie.lai(body[2:7])
    out["cell_selection"] = cell_selection(body[7:9])
    out["rach"] = rach_control(body[9:12])
    off = 12
    if off + 4 <= len(body) and body[off] == 0x64:
        out["cbch"] = ie.channel_description(body[off + 1:off + 4])
        off += 4
        if off + 2 <= len(body) and body[off] == 0x72:
            off += 2 + body[off + 1]
    out.update(si4_rest(rest))
    return out


def si13(body: bytes, rest: bytes) -> dict:
    return si13_rest(rest)


# Bits taken by FDD_CELL_INFORMATION / TDD_CELL_INFORMATION for N cells (44.018 9.1.54).
_P_FDD = (0, 10, 19, 28, 36, 44, 52, 60, 67, 74, 81, 88, 95, 102, 109, 116, 122)
_P_TDD = (0, 9, 17, 25, 32, 39, 46, 53, 59, 65, 71, 77, 83, 89, 95, 101, 106, 111, 116, 121, 126)


class _Unsupported(Exception):
    pass


def _utran_cells(r: BitReader, table: tuple[int, ...]) -> list[dict]:
    cells = []
    while r.bit():
        if r.bit():  # FDD-ARFCN-INDEX, reserved for earlier releases
            r.bits(3)
            continue
        uarfcn = r.bits(14)
        r.bit()  # FDD_Indic0 / TDD_Indic0
        n = r.bits(5)
        if n >= len(table):
            raise _Unsupported
        r.pos += table[n]
        if r.pos > r.end:
            raise BitsExhausted
        cells.append({"uarfcn": uarfcn, "cells": n})
    return cells


def si2quater(body: bytes, rest: bytes) -> dict:
    """SI2quater rest octets up to the 3G Neighbour Cell Description (44.018 10.5.2.33b)."""
    out: dict = {}
    r = BitReader(rest)
    try:
        out["ba_ind"] = r.bit()
        out["3g_ba_ind"] = r.bit()
        out["mp_change_mark"] = r.bit()
        out["index"] = r.bits(4)
        out["count"] = r.bits(4)
        if r.bit():  # Measurement Parameters Description
            r.bits(3)
        if r.bit():  # GPRS Real Time Difference Description
            raise _Unsupported
        if r.bit():  # GPRS BSIC Description
            if r.bit():
                r.bits(5)
            r.bits(6)
            r.bits(7 * r.bits(7))
        if r.bit():  # GPRS Report Priority Description
            r.bits(r.bits(7))
        if r.bit():  # GPRS Measurement Parameters Description
            r.bits(3)
            for _ in range(2):
                if r.bit():
                    r.bits(2)
            r.bits(2)
            for _ in range(5):
                if r.bit():
                    r.bits(6)
        if r.bit():  # NC Measurement Parameters
            r.bits(2)
            if r.bit():
                r.bits(9)
        if r.bit():  # SI2q Extension Information, length-prefixed
            n = r.bits(8)
            r.pos += n + 1
        if r.bit():  # 3G Neighbour Cell Description
            if r.bit():
                r.bits(7)
            if r.bit():
                r.bits(7)
            if r.bit():
                if r.bit():
                    r.bits(3)
                out["utran_fdd"] = _utran_cells(r, _P_FDD)
            if r.bit():
                if r.bit():
                    r.bits(3)
                out["utran_tdd"] = _utran_cells(r, _P_TDD)
    except (BitsExhausted, _Unsupported):
        pass
    return out


# --- dedicated channel messages ----------------------------------------------------

def si5(body: bytes, rest: bytes) -> dict:
    _need(body, 18)
    return _neighbours(body[2:18])


def si5ter(body: bytes, rest: bytes) -> dict:
    _need(body, 18)
    return si2ter(body, rest)


def si6(body: bytes, rest: bytes) -> dict:
    _need(body, 11)
    out = {"cell_id": (body[2] << 8) | body[3]}
    out.update(ie.lai(body[4:9]))
    b = body[9]
    out["cell_options"] = {"pwrc": bool(b & 0x40), "radio_link_timeout": ((b & 0x0F) + 1) * 4}
    out["ncc_permitted"] = [n for n in range(8) if body[10] >> n & 1]
    return out


def paging_response(body: bytes, rest: bytes) -> dict:
    _need(body, 4)
    cm2_len = body[3]
    off = 4 + cm2_len
    _need(body, off + 1)
    n = body[off]
    _need(body, off + 1 + n)
    return {"cksn": body[2] & 0x07, "identity": ie.mobile_identity(body[off + 1:off + 1 + n])}


def ciphering_mode_command(body: bytes, rest: bytes) -> dict:
    _need(body, 3)
    b = body[2]
    sc = bool(b & 0x01)
    return {
        "ciphering": sc,
        "algorithm": CIPHER_ALGOS[(b >> 1) & 0x07] if sc else "A5/0",
        "imeisv_requested": bool(b & 0x10),
    }


def channel_release(body: bytes, rest: bytes) -> dict:
    _need(body, 3)
    return {"cause": RR_CAUSES.get(body[2], f"0x{body[2]:02x}"), "cause_code": body[2]}


def assignment_command(body: bytes, rest: bytes) -> dict:
    _need(body, 5)
    return {"channel": ie.channel_description_2(body[2:5])}


HANDLERS = {
    0x21: paging_1,
    0x22: paging_2,
    0x24: paging_3,
    0x3F: immediate_assignment,
    0x39: immediate_assignment_ext,
    0x3A: immediate_assignment_reject,
    0x19: si1,
    0x1A: si2,
    0x02: si2bis,
    0x03: si2ter,
    0x07: si2quater,
    0x1B: si3,
    0x1C: si4,
    0x00: si13,
    0x1D: si5,
    0x05: si5,
    0x06: si5ter,
    0x1E: si6,
    0x27: paging_response,
    0x35: ciphering_mode_command,
    0x0D: channel_release,
    0x2E: assignment_command,
}


def decode(body: bytes, rest: bytes = b"") -> dict:
    """Decode an RR message; `body` starts at the protocol discriminator octet."""
    mt = body[1]
    msg = {"pd": "RR", "mt": mt, "name": MSG_NAMES.get(mt, f"RR 0x{mt:02x}")}
    handler = HANDLERS.get(mt)
    if handler is not None:
        try:
            msg.update(handler(body, rest))
        except (IEError, IndexError, BitsExhausted) as e:
            msg["error"] = str(e) or type(e).__name__
    return msg
