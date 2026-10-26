"""Stateful analysis: cells, identities, dedicated-channel sessions and events.

The tracker turns decoded messages into a model of what is on air:

* Cells are keyed by the ARFCN they were received on, so several receivers
  (or a frequency hopper) never mix up their cell identity.
* Identities (IMSI, TMSI, IMEI) are counted with where and how they were seen.
* Dedicated-channel sessions follow one phone through an SDCCH: the Immediate
  Assignment (timing advance, establishment cause), the initial message echoed
  in the network's UA frame (the identity the phone presented), then the
  network's replies (ciphering, location update result, TMSI reallocation).
* TMSI/IMSI links are only made from evidence inside one session, such as a
  Location Updating Accept that hands a new TMSI to the identity that asked.
"""

from __future__ import annotations

import time
from collections import Counter, deque
from collections.abc import Callable
from dataclasses import dataclass, field

from . import arfcn as arfcn_mod
from . import gsmtap
from .decoder import Decoded
from .ie import establishment_cause
from .plmn import Network, PlmnDB

SESSION_IDLE_S = 15.0
ASSIGNMENT_WINDOW_S = 3.0
PAGING_MATCH_S = 10.0
TMSI_RETAIN_S = 3600.0

_CHANNEL_FROM_DESC = {"SDCCH/8": gsmtap.CH_SDCCH8, "SDCCH/4": gsmtap.CH_SDCCH4,
                      "TCH/F": gsmtap.CH_TCH_F, "TCH/H": gsmtap.CH_TCH_H}
_INITIAL_MESSAGES = {
    "Location Updating Request": "location update",
    "CM Service Request": "service request",
    "Paging Response": "paging response",
    "IMSI Detach Indication": "IMSI detach",
    "CM Re-establishment Request": "re-establishment",
}


@dataclass
class Cell:
    arfcn: int
    pcs: bool = False
    mcc: str | None = None
    mnc: str | None = None
    lac: int | None = None
    ci: int | None = None
    network: Network | None = None
    first_seen: float = 0.0
    last_seen: float = 0.0
    signal_dbm: int | None = None
    neighbours: set[int] = field(default_factory=set)
    utran_neighbours: dict[int, int] = field(default_factory=dict)  # UARFCN -> cells listed
    cell_arfcns: list[int] = field(default_factory=list)
    ccch_conf: int | None = None
    neci: bool | None = None
    rxlev_access_min_dbm: int | None = None
    t3212_minutes: int | None = None
    cell_barred: bool | None = None
    band_indicator: str | None = None
    gprs: dict | None = None
    cbch: bool = False
    ciphers: Counter = field(default_factory=Counter)
    counters: Counter = field(default_factory=Counter)
    si_seen: set[str] = field(default_factory=set)

    @property
    def plmn(self) -> str | None:
        return f"{self.mcc}-{self.mnc}" if self.mcc else None

    @property
    def cgi(self) -> str | None:
        if self.mcc is None or self.lac is None or self.ci is None:
            return None
        return f"{self.mcc}-{self.mnc}-{self.lac}-{self.ci}"

    @property
    def band(self) -> str | None:
        pcs = self.pcs or self.band_indicator == "PCS1900"
        return arfcn_mod.band_of(self.arfcn, pcs)

    @property
    def downlink_mhz(self) -> float | None:
        pcs = self.pcs or self.band_indicator == "PCS1900"
        return arfcn_mod.downlink_mhz(self.arfcn, pcs)

    def summary(self) -> dict:
        return {
            "arfcn": self.arfcn,
            "band": self.band,
            "downlink_mhz": self.downlink_mhz,
            "mcc": self.mcc,
            "mnc": self.mnc,
            "lac": self.lac,
            "ci": self.ci,
            "operator": self.network.name if self.network else None,
            "country": self.network.country if self.network else None,
            "signal_dbm": self.signal_dbm,
            "neighbours": sorted(self.neighbours),
            "utran_neighbours": [
                {"uarfcn": u, "cells": n, "band": arfcn_mod.uarfcn_info(u)[0],
                 "downlink_mhz": arfcn_mod.uarfcn_info(u)[1]}
                for u, n in sorted(self.utran_neighbours.items())],
            "cell_arfcns": self.cell_arfcns,
            "ccch_conf": self.ccch_conf,
            "neci": self.neci,
            "rxlev_access_min_dbm": self.rxlev_access_min_dbm,
            "t3212_minutes": self.t3212_minutes,
            "cell_barred": self.cell_barred,
            "gprs": self.gprs,
            "cbch": self.cbch,
            "ciphers": dict(self.ciphers),
            "counters": dict(self.counters),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass
class Identity:
    kind: str
    value: str
    first_seen: float
    last_seen: float
    count: int = 0
    arfcn: int | None = None
    cgi: str | None = None
    sources: Counter = field(default_factory=Counter)
    ta: int | None = None
    distance_m: int | None = None
    links: set[tuple[str, str]] = field(default_factory=set)
    mcc: str | None = None
    mnc: str | None = None
    country: str | None = None
    operator: str | None = None

    @property
    def key(self) -> tuple[str, str]:
        return (self.kind, self.value)


@dataclass
class Session:
    arfcn: int
    timeslot: int
    channel: int
    sub_slot: int
    start: float
    last: float
    cause: str | None = None
    ta: int | None = None
    distance_m: int | None = None
    procedure: str | None = None
    identity: dict | None = None
    old_lai: dict | None = None
    service: str | None = None
    lu_type: str | None = None
    cipher: str | None = None
    new_identity: dict | None = None
    reject: str | None = None
    identity_requests: list[str] = field(default_factory=list)
    auth: str | None = None
    release: str | None = None
    messages: list[str] = field(default_factory=list)
    initial_info: bytes = b""

    def summary(self) -> dict:
        return {
            "arfcn": self.arfcn,
            "timeslot": self.timeslot,
            "channel": gsmtap.CHANNEL_NAMES.get(self.channel, str(self.channel)),
            "subchannel": self.sub_slot,
            "start": self.start,
            "duration_s": round(self.last - self.start, 3),
            "cause": self.cause,
            "ta": self.ta,
            "distance_m": self.distance_m,
            "procedure": self.procedure,
            "identity": self.identity,
            "old_lai": self.old_lai,
            "service": self.service,
            "lu_type": self.lu_type,
            "cipher": self.cipher,
            "new_identity": self.new_identity,
            "reject": self.reject,
            "identity_requests": self.identity_requests,
            "auth": self.auth,
            "release": self.release,
            "messages": self.messages,
        }


EventSink = Callable[[dict], None]


class Tracker:
    def __init__(self, db: PlmnDB, *, on_event: EventSink | None = None,
                 identity_ttl_s: float = 600.0, clock: Callable[[], float] = time.time) -> None:
        self.db = db
        self.on_event = on_event or (lambda e: None)
        self.identity_ttl_s = identity_ttl_s
        self.clock = clock
        self.cells: dict[int, Cell] = {}
        self.identities: dict[tuple[str, str], Identity] = {}
        self.sessions: dict[tuple, Session] = {}
        self._assignments: dict[tuple, tuple[float, dict]] = {}
        self._recent_pages: dict[tuple[str, str], float] = {}
        self.recent: deque[dict] = deque(maxlen=200)
        self.dirty: set[tuple[str, str]] = set()
        self.totals = Counter()
        self._last_housekeeping = 0.0
        self._last_prune = 0.0

    # --- helpers --------------------------------------------------------------

    def _emit(self, event: dict) -> None:
        self.recent.append(event)
        self.totals[f"event:{event['event']}"] += 1
        self.on_event(event)

    def cell(self, arfcn: int, pcs: bool = False) -> Cell:
        c = self.cells.get(arfcn)
        if c is None:
            c = self.cells[arfcn] = Cell(arfcn=arfcn, pcs=pcs)
        return c

    def split_imsi(self, imsi: str, cell: Cell | None = None) -> tuple[str, str, str]:
        serving = (cell.mcc, cell.mnc) if cell and cell.mcc else None
        return self.db.split_imsi(imsi, serving)

    def see_identity(self, ident: dict, ts: float, cell: Cell, source: str,
                     ta: int | None = None, distance_m: int | None = None) -> Identity | None:
        kind, value = ident.get("kind"), ident.get("value")
        if not value or kind not in ("imsi", "tmsi", "imei", "imeisv"):
            return None
        key = (kind, value)
        rec = self.identities.get(key)
        new = rec is None
        if new:
            rec = self.identities[key] = Identity(kind, value, ts, ts)
            if kind == "imsi":
                mcc, mnc, _ = self.split_imsi(value, cell)
                rec.mcc, rec.mnc = mcc, mnc
                net = self.db.network(mcc, mnc)
                rec.country = net.country if net else self.db.country(mcc)[0] or None
                rec.operator = net.name if net else None
            self.totals[f"unique:{kind}"] += 1
        rec.last_seen = ts
        rec.count += 1
        self.dirty.add(key)
        rec.arfcn = cell.arfcn
        rec.cgi = cell.cgi or rec.cgi
        rec.sources[source] += 1
        if ta is not None:
            rec.ta, rec.distance_m = ta, distance_m
        if new:
            self._emit({"event": "identity", "ts": ts, "kind": kind, "value": value,
                        "source": source, "arfcn": cell.arfcn, "cgi": cell.cgi,
                        "mcc": rec.mcc, "mnc": rec.mnc, "country": rec.country,
                        "operator": rec.operator, "foreign": bool(rec.mcc and cell.mcc and rec.mcc != cell.mcc),
                        "ta": ta, "distance_m": distance_m})
        return rec

    def link(self, a: dict, b: dict, reason: str, ts: float, cell: Cell) -> None:
        ra = self.see_identity(a, ts, cell, "link")
        rb = self.see_identity(b, ts, cell, "link")
        if ra is None or rb is None or ra is rb or rb.key in ra.links:
            return
        ra.links.add(rb.key)
        rb.links.add(ra.key)
        self._emit({"event": "link", "ts": ts, "a": a, "b": b, "reason": reason,
                    "arfcn": cell.arfcn, "cgi": cell.cgi})

    # --- main entry -------------------------------------------------------------

    def process(self, ts: float, d: Decoded) -> None:
        hdr = d.hdr
        self.totals["packets"] += 1
        if hdr.type != gsmtap.TYPE_UM or hdr.uplink:
            return
        cell = self.cell(hdr.arfcn, hdr.pcs)
        if not cell.first_seen:
            cell.first_seen = ts
        cell.last_seen = ts
        if hdr.channel in (gsmtap.CH_BCCH, gsmtap.CH_CCCH, gsmtap.CH_PCH, gsmtap.CH_AGCH):
            cell.signal_dbm = hdr.signal_dbm
        if hdr.channel in gsmtap.DEDICATED_CHANNELS:
            if hdr.channel == gsmtap.CH_SDCCH4 and cell.ccch_conf is not None and cell.ccch_conf != 1:
                return  # receiver demapped TS0 as combined, but the cell is not
            self._dedicated(ts, d, cell)
            return
        for msg in d.messages:
            cell.counters[msg["name"]] += 1
            handler = _CCCH_HANDLERS.get(msg["name"])
            if handler is not None and "error" not in msg:
                handler(self, ts, msg, cell)
        if ts - self._last_housekeeping > 5.0:
            self.housekeeping(ts)

    # --- broadcast ------------------------------------------------------------

    def _cell_identity(self, ts: float, msg: dict, cell: Cell) -> None:
        mcc, mnc, lac = msg.get("mcc"), msg.get("mnc"), msg.get("lac")
        ci = msg.get("cell_id", cell.ci)
        if mcc is None:
            return
        changed = (mcc, mnc, lac, ci) != (cell.mcc, cell.mnc, cell.lac, cell.ci)
        cell.mcc, cell.mnc, cell.lac, cell.ci = mcc, mnc, lac, ci
        if changed:
            cell.network = self.db.network(mcc, mnc)
            if ci is not None:
                self._emit({"event": "cell", "ts": ts, **cell.summary()})

    def _si3(self, ts: float, msg: dict, cell: Cell) -> None:
        cell.si_seen.add("SI3")
        cc = msg["control_channel"]
        cell.ccch_conf = cc["ccch_conf"]
        cell.t3212_minutes = cc["t3212_minutes"]
        cs = msg["cell_selection"]
        cell.neci = cs["neci"]
        cell.rxlev_access_min_dbm = cs["rxlev_access_min_dbm"]
        cell.cell_barred = msg["rach"]["cell_barred"]
        if msg.get("gprs"):
            cell.gprs = {**(cell.gprs or {}), **msg["gprs"]}
        self._cell_identity(ts, msg, cell)

    def _si4(self, ts: float, msg: dict, cell: Cell) -> None:
        cell.si_seen.add("SI4")
        cell.cbch = "cbch" in msg
        self._cell_identity(ts, msg, cell)

    def _si1(self, ts: float, msg: dict, cell: Cell) -> None:
        cell.si_seen.add("SI1")
        cell.cell_arfcns = msg["cell_arfcns"]
        if "band_indicator" in msg:
            cell.band_indicator = msg["band_indicator"]

    def _neighbour_si(self, ts: float, msg: dict, cell: Cell) -> None:
        cell.si_seen.add(msg["name"].replace("System Information Type ", "SI"))
        before = len(cell.neighbours)
        cell.neighbours.update(msg.get("neighbours", ()))
        if len(cell.neighbours) != before and cell.ci is not None:
            self._emit({"event": "neighbours", "ts": ts, "arfcn": cell.arfcn, "cgi": cell.cgi,
                        "neighbours": sorted(cell.neighbours)})

    def _si2quater(self, ts: float, msg: dict, cell: Cell) -> None:
        cell.si_seen.add("SI2quater")
        new = False
        for u in msg.get("utran_fdd", []) + msg.get("utran_tdd", []):
            if cell.utran_neighbours.get(u["uarfcn"]) != u["cells"]:
                cell.utran_neighbours[u["uarfcn"]] = u["cells"]
                new = True
        if new and cell.ci is not None:
            self._emit({"event": "neighbours", "ts": ts, "arfcn": cell.arfcn, "cgi": cell.cgi,
                        "neighbours": sorted(cell.neighbours),
                        "utran_neighbours": cell.summary()["utran_neighbours"]})

    def _si13(self, ts: float, msg: dict, cell: Cell) -> None:
        cell.si_seen.add("SI13")
        if "rac" in msg:
            g = dict(cell.gprs or {})
            g["rac"] = msg["rac"]
            opts = msg.get("gprs_cell_options", {})
            g["nmo"] = opts.get("nmo")
            g["egprs"] = opts.get("egprs")
            g["dtm"] = opts.get("dtm_support")
            cell.gprs = g

    def _paging(self, ts: float, msg: dict, cell: Cell) -> None:
        ids = msg.get("identities", [])
        cell.counters["paged identities"] += len(ids)
        if not ids:
            return
        for ident in ids:
            self.see_identity(ident, ts, cell, "paging")
            self._recent_pages[(ident["kind"], ident["value"])] = ts
        # P1/P2 rest octets flag pages that are for GPRS (packet paging) rather than CS.
        packet = [msg.get(f"packet_page_{i}") for i in (1, 2, 3)]
        self._emit({"event": "paging", "ts": ts, "arfcn": cell.arfcn, "cgi": cell.cgi,
                    "type": msg["name"], "identities": ids, "page_mode": msg.get("page_mode"),
                    "channel_needed": msg.get("channel_needed"),
                    "packet_paging": any(packet)})

    def _assignment(self, ts: float, a: dict, cell: Cell, name: str) -> None:
        chan = a["channel"]
        ref = a.get("request_reference", {})
        cause = establishment_cause(ref["ra"], cell.neci) if ref else None
        if not chan.get("tbf"):
            gch = _CHANNEL_FROM_DESC.get(chan.get("channel"))
            observable = not chan["hopping"] and chan.get("arfcn") == cell.arfcn
            # Only remember assignments we can actually receive; a channel on another
            # carrier with the same timeslot/subchannel is a different phone.
            if gch is not None and observable:
                key = (chan["arfcn"], chan["timeslot"], gch, chan.get("subchannel") or 0)
                self._assignments[key] = (ts, {"cause": cause, "ta": a.get("ta"),
                                               "distance_m": a.get("distance_m")})
        else:
            observable = False
        self._emit({"event": "assignment", "ts": ts, "arfcn": cell.arfcn, "cgi": cell.cgi,
                    "type": name, "cause": cause, "ra": ref.get("ra"), "ta": a.get("ta"),
                    "distance_m": a.get("distance_m"), "channel": chan, "observable": observable})

    def _ia(self, ts: float, msg: dict, cell: Cell) -> None:
        a = {"channel": dict(msg["channel"], tbf=msg["tbf"]), "request_reference": msg["request_reference"],
             "ta": msg["ta"], "distance_m": msg["distance_m"]}
        self._assignment(ts, a, cell, msg["name"])

    def _iax(self, ts: float, msg: dict, cell: Cell) -> None:
        for a in msg["assignments"]:
            self._assignment(ts, a, cell, msg["name"])

    def _iar(self, ts: float, msg: dict, cell: Cell) -> None:
        causes = [establishment_cause(r["ra"], cell.neci) for r in msg["rejects"]]
        self._emit({"event": "assignment_reject", "ts": ts, "arfcn": cell.arfcn, "cgi": cell.cgi,
                    "causes": causes, "wait_s": [r["wait_indication_s"] for r in msg["rejects"]]})

    # --- dedicated channels -----------------------------------------------------

    def _session(self, ts: float, d: Decoded, start: bool) -> Session | None:
        h = d.hdr
        key = (h.arfcn, h.timeslot, h.channel, h.sub_slot)
        s = self.sessions.get(key)
        if s is not None and (start or ts - s.last > SESSION_IDLE_S):
            self._close(key, s)
            s = None
        if s is None:
            s = Session(h.arfcn, h.timeslot, h.channel, h.sub_slot, ts, ts)
            pending = self._assignments.pop(key, None)
            if pending and ts - pending[0] <= ASSIGNMENT_WINDOW_S:
                info = pending[1]
                s.cause, s.ta, s.distance_m = info["cause"], info["ta"], info["distance_m"]
            self.sessions[key] = s
        s.last = ts
        return s

    def _close(self, key: tuple, s: Session) -> None:
        self.sessions.pop(key, None)
        if s.procedure is None and not s.messages:
            return
        cell = self.cells.get(s.arfcn)
        self.totals["sessions"] += 1
        if cell:
            cell.counters["sessions"] += 1
        self._emit({"event": "session", "ts": s.start, "cgi": cell.cgi if cell else None, **s.summary()})

    def _dedicated(self, ts: float, d: Decoded, cell: Cell) -> None:
        frame = d.frame
        if d.hdr.acch:
            for msg in d.messages:
                cell.counters[f"SACCH {msg['name']}"] += 1
                if msg["name"] in ("System Information Type 5", "System Information Type 5bis",
                                   "System Information Type 5ter") and "error" not in msg:
                    self._neighbour_si(ts, msg, cell)
                elif msg["name"] == "System Information Type 6" and "error" not in msg:
                    self._cell_identity(ts, msg, cell)
            if d.sacch:
                key = (d.hdr.arfcn, d.hdr.timeslot, d.hdr.channel, d.hdr.sub_slot)
                s = self.sessions.get(key)
                if s is not None and s.ta is None:
                    s.ta = d.sacch["ta"]
                    s.distance_m = round(s.ta * 553.5)
            return
        if frame is None or frame.sapi != 0:
            return  # SAPI 3 (SMS) is a separate link and does not start or end sessions
        if frame.func == "UA" and frame.info:
            key = (d.hdr.arfcn, d.hdr.timeslot, d.hdr.channel, d.hdr.sub_slot)
            cur = self.sessions.get(key)
            if cur is not None and cur.initial_info == frame.info and ts - cur.last <= SESSION_IDLE_S:
                cur.last = ts
                return  # UA repeated because the phone repeated its SABM
            s = self._session(ts, d, start=True)
            s.initial_info = frame.info
        elif frame.func in ("DISC", "DM"):
            key = (d.hdr.arfcn, d.hdr.timeslot, d.hdr.channel, d.hdr.sub_slot)
            s = self.sessions.get(key)
            if s is not None:
                s.messages.append(frame.func)
                self._close(key, s)
            return
        elif d.messages:
            s = self._session(ts, d, start=False)
        else:
            return
        for msg in d.messages:
            cell.counters[msg["name"]] += 1
            s.messages.append(msg["name"])
            if "error" in msg:
                continue
            self._dedicated_msg(ts, msg, s, cell)

    def _dedicated_msg(self, ts: float, msg: dict, s: Session, cell: Cell) -> None:
        name = msg["name"]
        if name in _INITIAL_MESSAGES:
            s.procedure = _INITIAL_MESSAGES[name]
            s.identity = msg.get("identity")
            s.old_lai = msg.get("old_lai") or msg.get("lai")
            s.service = msg.get("service")
            s.lu_type = msg.get("lu_type")
            if s.identity:
                rec = self.see_identity(s.identity, ts, cell, s.procedure.replace(" ", "_"),
                                        s.ta, s.distance_m)
                if name == "Paging Response" and rec is not None:
                    paged = self._recent_pages.get(rec.key)
                    if paged is not None and ts - paged <= PAGING_MATCH_S:
                        s.messages.append("(answers recent paging)")
        elif name == "Ciphering Mode Command":
            s.cipher = msg["algorithm"]
            cell.ciphers[msg["algorithm"]] += 1
            self._emit({"event": "cipher", "ts": ts, "arfcn": cell.arfcn, "cgi": cell.cgi,
                        "algorithm": msg["algorithm"], "identity": s.identity})
        elif name in ("Location Updating Accept", "TMSI Reallocation Command"):
            new = msg.get("identity")
            if new and new.get("value"):
                s.new_identity = new
                if s.identity and s.identity.get("value"):
                    self.link(s.identity, new, name, ts, cell)
                else:
                    self.see_identity(new, ts, cell, "reallocation")
        elif name in ("Location Updating Reject", "CM Service Reject"):
            s.reject = msg["cause"]
            cell.counters["rejects"] += 1
            self._emit({"event": "reject", "ts": ts, "arfcn": cell.arfcn, "cgi": cell.cgi,
                        "type": name, "cause": msg["cause"], "cause_code": msg["cause_code"],
                        "identity": s.identity, "old_lai": s.old_lai})
        elif name == "Identity Request":
            s.identity_requests.append(msg["identity_type"])
        elif name == "Authentication Request":
            s.auth = "UMTS AKA" if msg.get("umts_aka") else "GSM"
        elif name == "Channel Release":
            s.release = msg["cause"]
            key = (s.arfcn, s.timeslot, s.channel, s.sub_slot)
            self._close(key, s)
        elif name == "MM Information":
            info = {k: v for k, v in msg.items() if k not in ("pd", "mt", "name")}
            self._emit({"event": "mm_information", "ts": ts, "arfcn": cell.arfcn,
                        "cgi": cell.cgi, **info})

    # --- maintenance ----------------------------------------------------------------

    def housekeeping(self, now: float | None = None) -> None:
        now = self.clock() if now is None else now
        self._last_housekeeping = now
        for key, s in list(self.sessions.items()):
            if now - s.last > SESSION_IDLE_S:
                self._close(key, s)
        for key, (t, _) in list(self._assignments.items()):
            if now - t > ASSIGNMENT_WINDOW_S:
                del self._assignments[key]
        for key, t in list(self._recent_pages.items()):
            if now - t > PAGING_MATCH_S:
                del self._recent_pages[key]
        # TMSIs are reassigned constantly; drop stale ones so long runs stay bounded.
        # Sinks have already stored them (they flush every second).
        horizon = max(self.identity_ttl_s, TMSI_RETAIN_S)
        if now - self._last_prune > 60:
            self._last_prune = now
            for key, rec in list(self.identities.items()):
                if rec.kind == "tmsi" and now - rec.last_seen > horizon and key not in self.dirty:
                    del self.identities[key]

    def active_identities(self, now: float | None = None) -> list[Identity]:
        now = self.clock() if now is None else now
        return [i for i in self.identities.values() if now - i.last_seen <= self.identity_ttl_s]

    def close_all(self) -> None:
        for key, s in list(self.sessions.items()):
            self._close(key, s)


_CCCH_HANDLERS = {
    "System Information Type 1": Tracker._si1,
    "System Information Type 2": Tracker._neighbour_si,
    "System Information Type 2bis": Tracker._neighbour_si,
    "System Information Type 2ter": Tracker._neighbour_si,
    "System Information Type 3": Tracker._si3,
    "System Information Type 4": Tracker._si4,
    "System Information Type 2quater": Tracker._si2quater,
    "System Information Type 13": Tracker._si13,
    "Paging Request Type 1": Tracker._paging,
    "Paging Request Type 2": Tracker._paging,
    "Paging Request Type 3": Tracker._paging,
    "Immediate Assignment": Tracker._ia,
    "Immediate Assignment Extended": Tracker._iax,
    "Immediate Assignment Reject": Tracker._iar,
}
