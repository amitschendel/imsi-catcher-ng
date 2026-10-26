"""Command line interface."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from . import __version__, arfcn as arfcn_mod
from .decoder import Decoder
from .gsmtap import GSMTAP_PORT
from .plmn import PlmnDB
from .sinks import ConsoleSink, CsvSink, JsonlSink, Sink, SqliteSink, format_event
from .sources import PcapWriter, SniffSource, UdpSource, read_capture
from .tracker import Tracker

DISCLAIMER = ("For education and research on networks and devices you are authorized to monitor. "
              "Receiving or storing other people's identifiers may be illegal where you are.")


def _endpoint(text: str) -> tuple[str, int]:
    if ":" in text and not text.startswith("["):
        host, _, port = text.rpartition(":")
        return host or "127.0.0.1", int(port)
    if text.startswith("["):
        host, _, port = text[1:].partition("]:")
        return host, int(port)
    return "127.0.0.1", int(text)


def _freq_hz(args) -> float:
    if args.arfcn is not None:
        f = arfcn_mod.downlink_mhz(args.arfcn, args.pcs)
        if f is None:
            raise SystemExit(f"ARFCN {args.arfcn} is not in a known GSM band")
        return f * 1e6
    return arfcn_mod.parse_frequency(args.freq)


class App:
    def __init__(self, args) -> None:
        self.args = args
        self.db = PlmnDB.load(args.mcc_db)
        self.tracker = Tracker(self.db, on_event=self._on_event, identity_ttl_s=args.ttl)
        self.decoder = Decoder()
        self.sinks: list[Sink] = []
        self.dashboard = None
        self.pcap = PcapWriter(args.pcap) if args.pcap else None
        if args.jsonl:
            self.sinks.append(JsonlSink(args.jsonl))
        if args.sqlite:
            self.sinks.append(SqliteSink(args.sqlite))
        if args.csv:
            self.sinks.append(CsvSink(args.csv))
        self.watch = [w.replace(" ", "") for w in (args.watch or [])]

    def use_dashboard(self, live: bool) -> bool:
        if self.args.ui == "plain" or not live:
            return False
        if self.args.ui == "auto" and not sys.stdout.isatty():
            return False
        try:
            from .tui import Dashboard
        except ImportError:
            if self.args.ui == "tui":
                raise SystemExit("the dashboard needs 'rich' (pip install rich)")
            return False
        self.dashboard = Dashboard(self.tracker, show_tmsi=self.args.show_tmsi)
        self.sinks.append(self.dashboard)
        return True

    def _on_event(self, ev: dict) -> None:
        for s in self.sinks:
            s.event(ev)
        if self.watch and ev["event"] in ("identity", "paging", "session"):
            self._check_watch(ev)

    def _check_watch(self, ev: dict) -> None:
        values = []
        if ev["event"] == "identity":
            values.append(ev["value"])
        for i in ev.get("identities", []) + [ev.get("identity") or {}]:
            if i.get("value"):
                values.append(i["value"])
        for v in values:
            if any(v.startswith(w) for w in self.watch):
                msg = f"WATCH  {format_event(ev) or ev['event']}"
                if self.dashboard:
                    self.dashboard.log.append(msg)
                else:
                    print(msg, file=sys.stderr, flush=True)

    def feed(self, ts: float, dgram: bytes) -> None:
        if self.pcap:
            self.pcap.write(ts, dgram)
        d = self.decoder.decode(dgram)
        if d is not None:
            self.tracker.process(ts, d)

    def flush(self) -> None:
        for s in self.sinks:
            s.flush(self.tracker)
        self.tracker.dirty.clear()
        if self.pcap:
            self.pcap.flush()

    def close(self) -> None:
        self.tracker.close_all()
        for s in self.sinks:
            s.close(self.tracker)
        if self.pcap:
            self.pcap.close()

    def run_live(self, packets, tick=None) -> None:
        """Consume a live source; `tick` is called about once a second (e.g. frequency hopping)."""
        last = time.monotonic()
        dashboard = self.use_dashboard(live=True)
        if not dashboard:
            self.sinks.append(ConsoleSink(show_tmsi=self.args.show_tmsi))
            print(DISCLAIMER, file=sys.stderr)
        ctx = self.dashboard if dashboard else _Null()
        try:
            with ctx:
                for item in packets:
                    if item is not None:
                        self.feed(*item)
                    now = time.monotonic()
                    if now - last >= 1.0:
                        last = now
                        self.tracker.housekeeping(time.time())
                        if tick:
                            status = tick()
                            if self.dashboard and status:
                                self.dashboard.status = status
                        self.flush()
                        if self.dashboard:
                            self.dashboard.refresh()
        except KeyboardInterrupt:
            pass
        finally:
            self.close()
            print_summary(self.tracker)


class _Null:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def print_summary(t: Tracker, out=sys.stdout) -> None:
    print("", file=out)
    print(f"{'ARFCN':>5}  {'Band':<9} {'MHz':>7}  {'CGI':<22} {'Operator':<18} {'dBm':>4}  "
          f"{'Nbrs':>4}  {'Pages':>5}  Ciphers", file=out)
    for c in sorted(t.cells.values(), key=lambda c: c.arfcn):
        print(f"{c.arfcn:>5}  {c.band or '?':<9} {c.downlink_mhz or 0:>7.1f}  {c.cgi or '?':<22} "
              f"{(c.network.name if c.network else '?')[:18]:<18} {c.signal_dbm if c.signal_dbm is not None else '?':>4}  "
              f"{len(c.neighbours):>4}  {c.counters.get('paged identities', 0):>5}  "
              f"{' '.join(f'{k}:{v}' for k, v in sorted(c.ciphers.items())) or '-'}", file=out)
    for c in sorted(t.cells.values(), key=lambda c: c.arfcn):
        if c.utran_neighbours:
            umts = ", ".join(f"UARFCN {x['uarfcn']} ({x['band'] or '?'} {x['downlink_mhz'] or '?'} MHz, {x['cells']} cells)"
                             for x in c.summary()["utran_neighbours"])
            print(f"{c.arfcn:>5}  3G neighbours: {umts}", file=out)
    u = t.totals
    print(f"\npackets {u['packets']}  unique IMSI {u['unique:imsi']}  TMSI {u['unique:tmsi']}  "
          f"IMEI {u['unique:imei'] + u['unique:imeisv']}  sessions {u['sessions']}  "
          f"links {u['event:link']}  rejects {u['event:reject']}", file=out)
    imsis = sorted((i for i in t.identities.values() if i.kind != "tmsi"), key=lambda i: i.first_seen)
    if imsis:
        print(f"\n{'Kind':<6} {'Identity':<26} {'Country':<16} {'Operator':<16} {'Count':>5}  Via", file=out)
        for i in imsis:
            via = ",".join(f"{k}" for k, _ in i.sources.most_common(3))
            print(f"{i.kind.upper():<6} {i.value:<26} {(i.country or '')[:16]:<16} "
                  f"{(i.operator or '')[:16]:<16} {i.count:>5}  {via}", file=out)


# --- commands -------------------------------------------------------------------

def cmd_listen(args) -> int:
    app = App(args)
    endpoints = [_endpoint(e) for e in (args.udp or [f"127.0.0.1:{GSMTAP_PORT}"])]
    src = UdpSource(endpoints)
    print(f"listening for GSMTAP on {', '.join(f'{h}:{p}' for h, p in endpoints)}", file=sys.stderr)
    app.run_live(src.packets())
    return 0


def cmd_sniff(args) -> int:
    app = App(args)
    src = SniffSource(args.iface, frozenset(args.port))
    app.run_live(src.packets())
    return 0


def cmd_read(args) -> int:
    app = App(args)
    if not args.quiet:
        app.sinks.append(ConsoleSink(show_tmsi=args.show_tmsi))
    t0 = time.perf_counter()
    n = 0
    last_ts = 0.0
    for path in args.files:
        for ts, dgram in read_capture(path, ports=None if args.any_port else frozenset(args.port)):
            app.feed(ts, dgram)
            n += 1
            if ts - last_ts > 5:
                app.flush()
                app.tracker.housekeeping(ts)
                last_ts = ts
    app.close()
    dt = time.perf_counter() - t0
    print_summary(app.tracker)
    print(f"\n{n} packets in {dt:.2f}s ({n / dt if dt else 0:,.0f} packets/s)", file=sys.stderr)
    return 0


def _livemon_kw(args, port: int) -> dict:
    log = Path(args.livemon_log) if args.livemon_log else None
    return {"collector_port": port, "gain": args.gain, "ppm": args.ppm, "args": args.device_args, "log": log}


HIGH_BANDS = {"DCS1800", "PCS1900"}


def _warn_rtl_range(bands, device_args: str) -> None:
    if "rtl" in device_args and HIGH_BANDS.intersection(bands):
        print("warning: RTL-SDR tuners (R820T, R828D) stop around 1.75 GHz and cannot receive "
              "DCS1800/PCS1900 (1805 MHz and up); this scan will find nothing", file=sys.stderr)


def cmd_scan(args) -> int:
    from .radio import scan

    db = PlmnDB.load(args.mcc_db)
    bands = args.band or ["GSM900"]
    _warn_rtl_range(bands, args.device_args)
    print(f"scanning {', '.join(bands)}; on a Raspberry Pi this takes 20 minutes or more per band",
          file=sys.stderr)
    rows = []
    for band in bands:
        rows += scan(band, gain=args.gain, ppm=args.ppm, speed=args.speed, args=args.device_args,
                     progress=lambda line, b=band: print(f"[{b}] {line}", file=sys.stderr, flush=True))
    rows.sort(key=lambda r: -r.power_db)
    print(f"{'ARFCN':>5} {'MHz':>7} {'Pwr':>4}  {'PLMN':<7} {'LAC':>5} {'CID':>6}  {'Operator':<20} Neighbours")
    for r in rows:
        mcc = f"{r.mcc:03d}"
        # grgsm_scanner prints the MNC as an integer; recover its width from the table.
        net = db.network(mcc, f"{r.mnc:02d}") or db.network(mcc, f"{r.mnc:03d}")
        plmn = f"{mcc}-{net.mnc}" if net else ("?" if r.mcc == 0 else f"{mcc}-{r.mnc:02d}")
        cid = str(r.cid) if r.cid or r.lac else "?"
        lac = str(r.lac) if r.lac else "?"
        print(f"{r.arfcn:>5} {r.freq_mhz:>7.1f} {r.power_db:>4}  {plmn:<7} {lac:>5} {cid:>6}  "
              f"{(net.name if net else '?')[:20]:<20} {' '.join(map(str, r.neighbours))}")
    if any(not r.cid for r in rows):
        print("\n? = not decoded by grgsm_scanner; 'imsi-catcher live --arfcn N' decodes the full cell identity",
              file=sys.stderr)
    return 0 if rows else 1


def cmd_live(args) -> int:
    from .radio import scan

    if args.freq is None and args.arfcn is None and not args.auto:
        raise SystemExit("give --freq, --arfcn or --auto")
    if args.auto:
        found = []
        _warn_rtl_range(args.band or ["GSM900"], args.device_args)
        for band in args.band or ["GSM900"]:
            print(f"scanning {band}...", file=sys.stderr)
            found += scan(band, gain=args.gain, ppm=args.ppm, args=args.device_args,
                          progress=lambda line, b=band: print(f"[{b}] {line}", file=sys.stderr, flush=True))
        if not found:
            raise SystemExit("no GSM cells found")
        found.sort(key=lambda r: -r.power_db)
        freqs = [r.freq_mhz * 1e6 for r in found[: args.auto]]
    else:
        freqs = [_freq_hz(args)]
    return _run_receiver(args, freqs)


def cmd_hop(args) -> int:
    freqs = []
    for f in args.targets:
        if f.lower().startswith("arfcn:") or f.isdigit():
            n = int(f.split(":")[-1])
            mhz = arfcn_mod.downlink_mhz(n, args.pcs)
            if mhz is None:
                raise SystemExit(f"ARFCN {n} is not in a known GSM band")
            freqs.append(mhz * 1e6)
        else:
            freqs.append(arfcn_mod.parse_frequency(f))
    return _run_receiver(args, freqs)


def _run_receiver(args, freqs: list[float]) -> int:
    from .radio import Hopper

    app = App(args)
    port = args.port_in or 0
    src = UdpSource([("127.0.0.1", port)])
    port = src.sockets[0].getsockname()[1]
    hopper = Hopper(freqs, args.dwell, **_livemon_kw(args, port))

    def tick() -> str:
        hopper.tick()
        f = hopper.freqs[hopper.index] / 1e6
        a = arfcn_mod.arfcn_from_downlink(f)
        return f"rx {f:.1f} MHz" + (f" (ARFCN {a})" if a is not None else "") + (
            f"  hop {hopper.index + 1}/{len(freqs)}" if len(freqs) > 1 else "")

    from .radio import ReceiverError

    tick()
    try:
        app.run_live(src.packets(), tick=tick)
    except ReceiverError as e:
        print(f"\nerror: {e}", file=sys.stderr)
        return 2
    finally:
        hopper.stop()
    return 0


def cmd_db(args) -> int:
    db = PlmnDB.load(args.mcc_db)
    if args.mnc is None:
        country, iso = db.country(args.mcc)
        print(f"{args.mcc}: {country or 'unknown'} {iso}")
        return 0
    net = db.network(args.mcc, args.mnc)
    if net is None:
        print(f"{args.mcc}-{args.mnc}: unknown")
        return 1
    print(f"{net.mcc}-{net.mnc}: {net.name} ({net.operator}), {net.country} {net.iso}, {net.status}; {net.bands}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="imsi-catcher",
        description="Passive GSM broadcast and signalling analyser for GSMTAP streams. " + DISCLAIMER,
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    out = argparse.ArgumentParser(add_help=False)
    g = out.add_argument_group("output")
    g.add_argument("--ui", choices=("auto", "tui", "plain"), default="auto",
                   help="live dashboard (needs rich) or one line per event (default: auto)")
    g.add_argument("--jsonl", metavar="PATH", help="append events as JSON lines ('-' for stdout)")
    g.add_argument("--sqlite", metavar="PATH", help="store events, identities and cells in SQLite")
    g.add_argument("--csv", metavar="PATH", help="write an identity snapshot as CSV")
    g.add_argument("--pcap", metavar="PATH", help="save the raw GSMTAP stream for Wireshark")
    g.add_argument("--show-tmsi", action="store_true", help="also list TMSIs in the console and dashboard")
    g.add_argument("--watch", metavar="PREFIX", action="append",
                   help="alert when an identity starting with PREFIX is seen (repeatable)")
    g.add_argument("--ttl", type=float, default=600, help="seconds an identity stays in the live table")
    g.add_argument("--mcc-db", metavar="PATH", help="alternative mcc_mnc.json")

    rx = argparse.ArgumentParser(add_help=False)
    r = rx.add_argument_group("receiver (gr-gsm)")
    r.add_argument("-g", "--gain", type=float, default=30.0, help="RF gain in dB (default 30)")
    r.add_argument("-p", "--ppm", type=float, default=0.0, help="oscillator correction in ppm")
    r.add_argument("--device-args", default="rtl=0", metavar="ARGS",
                   help="osmosdr device string (default rtl=0; gr-gsm's own device autodetection "
                        "fails with recent gr-osmosdr, so a value is always passed)")
    r.add_argument("--pcs", action="store_true", help="treat ARFCN 512-810 as PCS1900 instead of DCS1800")
    r.add_argument("--livemon-log", metavar="PATH", help="write grgsm_livemon output to this file")
    r.add_argument("--port-in", type=int, metavar="PORT",
                   help="local UDP port for livemon's GSMTAP (default: any free port)")
    r.add_argument("--dwell", type=float, default=60.0, help="seconds per frequency when hopping")

    s = sub.add_parser("listen", parents=[out], help="analyse GSMTAP arriving on UDP (default 127.0.0.1:4729)")
    s.add_argument("--udp", action="append", metavar="[HOST:]PORT",
                   help="UDP endpoint to bind; repeat for several receivers")
    s.set_defaults(func=cmd_listen)

    s = sub.add_parser("sniff", parents=[out], help="capture GSMTAP on a network interface (Linux, root)")
    s.add_argument("-i", "--iface", default="lo")
    s.add_argument("--port", type=int, action="append", default=None)
    s.set_defaults(func=cmd_sniff)

    s = sub.add_parser("read", parents=[out], help="analyse pcap/pcapng captures")
    s.add_argument("files", nargs="+")
    s.add_argument("--port", type=int, action="append", default=None, help="GSMTAP UDP port (default 4729)")
    s.add_argument("--any-port", action="store_true", help="treat every UDP payload as GSMTAP")
    s.add_argument("-q", "--quiet", action="store_true", help="only print the final summary")
    s.set_defaults(func=cmd_read)

    s = sub.add_parser("scan", parents=[rx], help="find GSM cells with grgsm_scanner")
    s.add_argument("-b", "--band", action="append", choices=("GSM900", "DCS1800", "GSM850", "PCS1900",
                                                              "GSM450", "GSM480", "GSM-R"))
    s.add_argument("--speed", type=int, default=15, choices=range(30), metavar="0-29",
                   help="grgsm_scanner speed: each tuning step records for 30 minus this many "
                        "seconds, so higher is faster and may miss weak cells (default 15)")
    s.add_argument("--mcc-db", metavar="PATH")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("live", parents=[out, rx], help="run grgsm_livemon on one cell and analyse it")
    s.add_argument("-f", "--freq", help="downlink frequency, e.g. 947.2M")
    s.add_argument("-a", "--arfcn", type=int, help="ARFCN instead of a frequency")
    s.add_argument("--auto", type=int, nargs="?", const=1, metavar="N",
                   help="scan first, then monitor the N strongest cells (hopping if N > 1)")
    s.add_argument("-b", "--band", action="append", help="bands for --auto (default GSM900)")
    s.set_defaults(func=cmd_live)

    s = sub.add_parser("hop", parents=[out, rx], help="rotate one receiver over several cells")
    s.add_argument("targets", nargs="+", help="frequencies (947.2M) or ARFCNs (arfcn:61 or 61)")
    s.set_defaults(func=cmd_hop)

    s = sub.add_parser("db", help="look up an MCC or MCC/MNC pair")
    s.add_argument("mcc")
    s.add_argument("mnc", nargs="?")
    s.add_argument("--mcc-db", metavar="PATH")
    s.set_defaults(func=cmd_db)
    return p


def main(argv: list[str] | None = None) -> int:
    from .radio import ReceiverError

    args = build_parser().parse_args(argv)
    if getattr(args, "port", "unset") is None:
        args.port = [GSMTAP_PORT]
    try:
        return args.func(args)
    except (ReceiverError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
