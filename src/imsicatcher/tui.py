"""Live terminal dashboard built on rich."""

from __future__ import annotations

import time
from collections import deque
from datetime import datetime

from rich.console import Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .sinks import Sink, format_event
from .tracker import Tracker


_CCCH = {0: "1 basic", 1: "combined", 2: "2 basic", 4: "3 basic", 6: "4 basic"}


def _ago(now: float, ts: float) -> str:
    d = max(0, int(now - ts))
    return f"{d}s" if d < 120 else f"{d // 60}m"


class Dashboard(Sink):
    def __init__(self, tracker: Tracker, *, show_tmsi: bool = False,
                 rows: int = 20, title: str = "imsi-catcher-ng") -> None:
        self.t = tracker
        self.show_tmsi = show_tmsi
        self.rows = rows
        self.title = title
        self.log: deque[str] = deque(maxlen=12)
        self.live: Live | None = None
        self._rate: deque[tuple[float, int]] = deque(maxlen=20)
        self.status = ""

    def event(self, ev: dict) -> None:
        line = format_event(ev)
        if line:
            self.log.append(line)

    def __enter__(self) -> "Dashboard":
        self.live = Live(self.render(), refresh_per_second=2, screen=True, transient=False)
        self.live.__enter__()
        return self

    def __exit__(self, *exc) -> None:
        if self.live:
            self.live.update(self.render())
            self.live.__exit__(*exc)

    def refresh(self) -> None:
        if self.live:
            self.live.update(self.render())

    def _cells(self, now: float) -> Table:
        tb = Table(expand=True, box=None, header_style="bold")
        for col in ("ARFCN", "Band", "MHz", "PLMN", "Operator", "LAC", "CI", "dBm", "Nbrs", "3G",
                    "CCCH", "GPRS", "Ciphers", "Pages", "Seen"):
            tb.add_column(col, no_wrap=True)
        for c in sorted(self.t.cells.values(), key=lambda c: -c.last_seen):
            g = c.gprs or {}
            gprs = "-" if not g else ("EDGE" if g.get("egprs") else "GPRS") + (
                f" NMO {g['nmo']}" if g.get("nmo") else "")
            ciphers = " ".join(f"{k}:{v}" for k, v in sorted(c.ciphers.items())) or "-"
            tb.add_row(
                str(c.arfcn), c.band or "?", f"{c.downlink_mhz or 0:.1f}", c.plmn or "?",
                (c.network.name if c.network else "?")[:18], str(c.lac or "?"), str(c.ci or "?"),
                str(c.signal_dbm if c.signal_dbm is not None else "?"), str(len(c.neighbours)),
                " ".join(str(u) for u in sorted(c.utran_neighbours)) or "-",
                _CCCH.get(c.ccch_conf, "-"),
                gprs, ciphers, str(c.counters.get("paged identities", 0)), _ago(now, c.last_seen),
            )
        return tb

    def _identities(self, now: float) -> Table:
        tb = Table(expand=True, box=None, header_style="bold")
        for col in ("Kind", "Identity", "Country", "Operator", "Count", "Via", "Cell", "TA", "Links", "Last"):
            tb.add_column(col, no_wrap=True)
        idents = [i for i in self.t.active_identities(now) if self.show_tmsi or i.kind != "tmsi"]
        idents.sort(key=lambda i: -i.last_seen)
        for i in idents[: self.rows]:
            via = ",".join(k for k, _ in i.sources.most_common(2))
            ta = f"{i.ta} ~{i.distance_m}m" if i.ta is not None else "-"
            links = " ".join(v for _, v in sorted(i.links))[:30] or "-"
            tb.add_row(i.kind.upper(), i.value, (i.country or "")[:14],
                       (i.operator or "")[:16], str(i.count), via, i.cgi or str(i.arfcn), ta, links,
                       _ago(now, i.last_seen))
        return tb

    def render(self):
        now = time.time()
        pk = self.t.totals["packets"]
        self._rate.append((now, pk))
        rate = 0.0
        if len(self._rate) > 1 and self._rate[-1][0] > self._rate[0][0]:
            rate = (self._rate[-1][1] - self._rate[0][1]) / (self._rate[-1][0] - self._rate[0][0])
        u = self.t.totals
        header = Text.assemble(
            (f"{self.title}  ", "bold"),
            f"{datetime.now():%H:%M:%S}  packets {pk} ({rate:.0f}/s)  ",
            f"IMSI {u['unique:imsi']}  TMSI {u['unique:tmsi']}  IMEI {u['unique:imei'] + u['unique:imeisv']}  ",
            f"sessions {u['sessions']}  {self.status}",
        )
        layout = Layout()
        layout.split_column(
            Layout(Panel(header, padding=(0, 1)), size=3),
            Layout(Panel(self._cells(now), title="Cells"), size=max(5, len(self.t.cells) + 4)),
            Layout(Panel(self._identities(now), title="Identities")),
            Layout(Panel(Group(*[Text(x, overflow="ellipsis", no_wrap=True) for x in self.log]),
                         title="Events"), size=14),
        )
        return layout
