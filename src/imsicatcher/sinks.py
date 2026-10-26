"""Output sinks: JSON lines, SQLite, CSV and the console."""

from __future__ import annotations

import csv
import json
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import TextIO

from .tracker import Identity, Tracker


def identity_row(i: Identity) -> dict:
    return {
        "kind": i.kind,
        "identity": i.value,
        "mcc": i.mcc,
        "mnc": i.mnc,
        "country": i.country,
        "operator": i.operator,
        "first_seen": i.first_seen,
        "last_seen": i.last_seen,
        "count": i.count,
        "arfcn": i.arfcn,
        "cgi": i.cgi,
        "ta": i.ta,
        "distance_m": i.distance_m,
        "sources": dict(i.sources),
        "links": sorted(f"{k}:{v}" for k, v in i.links),
    }


class Sink:
    def event(self, ev: dict) -> None: ...
    def flush(self, tracker: Tracker) -> None: ...
    def close(self, tracker: Tracker) -> None:
        self.flush(tracker)


class JsonlSink(Sink):
    def __init__(self, path: str) -> None:
        self.f: TextIO = sys.stdout if path == "-" else open(path, "a", encoding="utf-8")

    def event(self, ev: dict) -> None:
        self.f.write(json.dumps(ev, ensure_ascii=False, default=str) + "\n")

    def flush(self, tracker: Tracker) -> None:
        self.f.flush()

    def close(self, tracker: Tracker) -> None:
        self.f.flush()
        if self.f is not sys.stdout:
            self.f.close()


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    event TEXT NOT NULL,
    arfcn INTEGER,
    cgi TEXT,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_kind ON events(event);
CREATE TABLE IF NOT EXISTS identities (
    kind TEXT NOT NULL,
    identity TEXT NOT NULL,
    mcc TEXT, mnc TEXT, country TEXT, operator TEXT,
    first_seen REAL, last_seen REAL, count INTEGER,
    arfcn INTEGER, cgi TEXT, ta INTEGER, distance_m INTEGER,
    sources TEXT, links TEXT,
    PRIMARY KEY (kind, identity)
);
CREATE TABLE IF NOT EXISTS cells (
    arfcn INTEGER NOT NULL,
    cgi TEXT NOT NULL,
    mcc TEXT, mnc TEXT, lac INTEGER, ci INTEGER,
    operator TEXT, band TEXT, downlink_mhz REAL,
    first_seen REAL, last_seen REAL,
    summary TEXT,
    PRIMARY KEY (arfcn, cgi)
);
"""


class SqliteSink(Sink):
    """Batches events and upserts identity/cell snapshots on each flush."""

    def __init__(self, path: str, batch: int = 500) -> None:
        self.db = sqlite3.connect(path)
        self.db.executescript(SCHEMA)
        self.batch = batch
        self.pending: list[tuple] = []

    def event(self, ev: dict) -> None:
        self.pending.append((ev["ts"], ev["event"], ev.get("arfcn"), ev.get("cgi"),
                             json.dumps(ev, ensure_ascii=False, default=str)))
        if len(self.pending) >= self.batch:
            self._write_events()

    def _write_events(self) -> None:
        if self.pending:
            self.db.executemany("INSERT INTO events(ts, event, arfcn, cgi, data) VALUES (?,?,?,?,?)",
                                self.pending)
            self.pending.clear()

    def flush(self, tracker: Tracker) -> None:
        self._write_events()
        rows = []
        for key in tracker.dirty:
            i = tracker.identities.get(key)
            if i is None:
                continue
            row = identity_row(i)
            rows.append((row["kind"], row["identity"], row["mcc"], row["mnc"], row["country"],
                         row["operator"], row["first_seen"], row["last_seen"], row["count"],
                         row["arfcn"], row["cgi"], row["ta"], row["distance_m"],
                         json.dumps(row["sources"]), json.dumps(row["links"])))
        if rows:
            self.db.executemany(
                """INSERT INTO identities VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(kind, identity) DO UPDATE SET
                     last_seen=excluded.last_seen, count=excluded.count, arfcn=excluded.arfcn,
                     cgi=excluded.cgi, ta=COALESCE(excluded.ta, ta),
                     distance_m=COALESCE(excluded.distance_m, distance_m),
                     sources=excluded.sources, links=excluded.links""", rows)
        cells = []
        for c in tracker.cells.values():
            if c.cgi is None:
                continue
            cells.append((c.arfcn, c.cgi, c.mcc, c.mnc, c.lac, c.ci,
                          c.network.name if c.network else None, c.band, c.downlink_mhz,
                          c.first_seen, c.last_seen, json.dumps(c.summary(), default=str)))
        if cells:
            self.db.executemany(
                """INSERT INTO cells VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(arfcn, cgi) DO UPDATE SET
                     last_seen=excluded.last_seen, summary=excluded.summary""", cells)
        self.db.commit()

    def close(self, tracker: Tracker) -> None:
        self.flush(tracker)
        self.db.close()


class CsvSink(Sink):
    """Rewrites an identity snapshot on every flush."""

    FIELDS = ["kind", "identity", "mcc", "mnc", "country", "operator", "first_seen", "last_seen",
              "count", "arfcn", "cgi", "ta", "distance_m", "sources", "links"]

    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self._last = 0.0

    def flush(self, tracker: Tracker, force: bool = False) -> None:
        if not force and time.monotonic() - self._last < 10:
            return
        self._last = time.monotonic()
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with open(tmp, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=self.FIELDS)
            w.writeheader()
            for i in sorted(tracker.identities.values(), key=lambda x: x.first_seen):
                row = identity_row(i)
                row["first_seen"] = _iso(row["first_seen"])
                row["last_seen"] = _iso(row["last_seen"])
                row["sources"] = ";".join(f"{k}={v}" for k, v in row["sources"].items())
                row["links"] = ";".join(row["links"])
                w.writerow(row)
        tmp.replace(self.path)

    def close(self, tracker: Tracker) -> None:
        self.flush(tracker, force=True)


def _iso(ts: float | None) -> str:
    return datetime.fromtimestamp(ts).isoformat(timespec="seconds") if ts else ""


def _clock(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def _ident(i: dict | None) -> str:
    if not i:
        return "-"
    return f"{i['kind'].upper()} {i.get('value')}"


def format_event(ev: dict) -> str | None:
    """One human-readable line per event, or None for events not worth a line."""
    e = ev["event"]
    t = _clock(ev["ts"])
    where = f"ARFCN {ev.get('arfcn')}" + (f" {ev['cgi']}" if ev.get("cgi") else "")
    if e == "cell":
        op = ev.get("operator") or "unknown operator"
        return (f"{t} CELL     {where}  {op} ({ev.get('country') or '?'}), {ev.get('band')} "
                f"{ev.get('downlink_mhz')} MHz, {ev.get('signal_dbm')} dBm")
    if e == "identity":
        if ev["kind"] == "tmsi":
            return None
        bits = [ev.get("operator") or "", ev.get("country") or ""]
        extra = ", ".join(b for b in bits if b)
        if ev.get("foreign"):
            extra += ", roaming"
        if ev.get("ta") is not None:
            extra += f", TA {ev['ta']} (~{ev['distance_m']} m)"
        return f"{t} NEW      {where}  {ev['kind'].upper()} {ev['value']}  via {ev['source']}  {extra}".rstrip()
    if e == "link":
        return f"{t} LINK     {where}  {_ident(ev['a'])} <-> {_ident(ev['b'])}  ({ev['reason']})"
    if e == "session":
        parts = [ev.get("procedure") or "session", _ident(ev.get("identity"))]
        if ev.get("cause"):
            parts.append(f"cause: {ev['cause']}")
        if ev.get("ta") is not None:
            parts.append(f"TA {ev['ta']} (~{ev['distance_m']} m)")
        if ev.get("cipher"):
            parts.append(ev["cipher"])
        if ev.get("reject"):
            parts.append(f"rejected: {ev['reject']}")
        if ev.get("new_identity"):
            parts.append(f"new {_ident(ev['new_identity'])}")
        return f"{t} SESSION  {where}  " + ", ".join(parts)
    if e == "reject":
        return f"{t} REJECT   {where}  {ev['type']}: {ev['cause']}  {_ident(ev.get('identity'))}"
    if e == "mm_information":
        name = ev.get("network_full_name") or ev.get("network_short_name") or ""
        return f"{t} MM INFO  {where}  network name {name!r} time {ev.get('network_time_utc')}"
    if e == "neighbours" and ev.get("utran_neighbours"):
        umts = ", ".join(f"{x['uarfcn']} ({x['band'] or '?'}, {x['cells']} cells)" for x in ev["utran_neighbours"])
        return f"{t} 3G NBR   {where}  UARFCN {umts}"
    if e == "assignment_reject":
        return f"{t} IA REJ   {where}  {', '.join(ev['causes'])}"
    return None


class ConsoleSink(Sink):
    def __init__(self, stream: TextIO = sys.stdout, show_tmsi: bool = False) -> None:
        self.stream = stream
        self.show_tmsi = show_tmsi

    def event(self, ev: dict) -> None:
        if self.show_tmsi and ev["event"] == "identity" and ev["kind"] == "tmsi":
            line = f"{_clock(ev['ts'])} NEW      ARFCN {ev['arfcn']}  TMSI {ev['value']}  via {ev['source']}"
        else:
            line = format_event(ev)
        if line:
            print(line, file=self.stream, flush=True)
