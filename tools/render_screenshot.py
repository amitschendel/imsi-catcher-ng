#!/usr/bin/env python3
"""Render docs/dashboard.svg from made-up traffic.

Usage: render_screenshot.py [--out docs/dashboard.svg]

The cells use the test network 001-01 and every identity is random, so the
image shows the dashboard without any real subscriber or cell data. The
README uses a PNG of it (on macOS: qlmanage -t -s 1800 -o docs docs/dashboard.svg).
"""

import argparse
import io
import random
import sys
import time
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))
sys.path.insert(0, str(root / "tests"))

from rich.console import Console  # noqa: E402

from imsicatcher import gsmtap  # noqa: E402
from imsicatcher.decoder import Decoder  # noqa: E402
from imsicatcher.plmn import PlmnDB  # noqa: E402
from imsicatcher.tracker import Tracker  # noqa: E402
from imsicatcher.tui import Dashboard  # noqa: E402
import synth  # noqa: E402

rng = random.Random(7)
HOMES = ["00101", "00101", "00101", "26201", "20810", "310260", "23415", "72405", "42502"]


def imsi() -> str:
    home = rng.choice(HOMES)
    return home + "".join(rng.choice("0123456789") for _ in range(15 - len(home)))


def si3(arfcn, lac, ci, dbm):
    l3 = (bytes([0x06, 0x1B]) + ci.to_bytes(2, "big") + synth.lai_bytes("001", "01", lac)
          + bytes([0x00, 0x03, 0x0A, 0x05, 0x00, 0x46, 0x00, 0x00, 0x00]))
    return synth.gsmtap_pkt(synth.bbis(l3, b"\x2b" * 4), gsmtap.CH_BCCH, arfcn=arfcn, signal_dbm=dbm)


DBM = {17: -51, 975: -63, 52: -77}


def si2(arfcn, neighbours):
    v = bytearray(16)
    for a in neighbours:
        v[15 - ((a - 1) >> 3)] |= 1 << ((a - 1) & 7)
    l3 = bytes([0x06, 0x1A]) + bytes(v) + bytes([0xFF, 0, 0, 0])
    return synth.gsmtap_pkt(synth.bbis(l3), gsmtap.CH_BCCH, arfcn=arfcn, signal_dbm=DBM[arfcn])


def ia(arfcn, sub, ta, ra):
    cd = bytes([(0b01000 | sub) << 3 | 1, arfcn >> 8, arfcn & 0xFF])
    l3 = bytes([0x06, 0x3F, 0x00]) + cd + bytes([ra, 0, 0, ta, 0])
    return synth.gsmtap_pkt(synth.bbis(l3), gsmtap.CH_CCCH, arfcn=arfcn, signal_dbm=DBM[arfcn])


def sd(frame, arfcn, sub):
    return synth.gsmtap_pkt(frame, gsmtap.CH_SDCCH8, arfcn=arfcn, timeslot=1, sub_slot=sub)


def paging(arfcn, ident: bytes):
    l3 = bytes([0x06, 0x21, 0x00]) + synth.lv(ident)
    return synth.gsmtap_pkt(synth.bbis(l3), gsmtap.CH_CCCH, arfcn=arfcn, signal_dbm=DBM[arfcn])


def session(arfcn, sub, ident: bytes, *, accept: bool, cause: int = 13):
    out = [ia(arfcn, sub, rng.randrange(0, 6), 0x05)]
    l3 = bytes([0x05, 0x08, 0x70]) + synth.lai_bytes("001", "01", 99) + b"\x57" + synth.lv(ident)
    out.append(sd(synth.ua(l3), arfcn, sub))
    if accept:
        out.append(sd(synth.iframe(bytes([0x06, 0x35, 0x01])), arfcn, sub))
        new = synth.mi_tmsi(rng.randbytes(4))
        acc = bytes([0x05, 0x02]) + synth.lai_bytes("001", "01", 100) + b"\x17" + synth.lv(new)
        out.append(sd(synth.iframe(acc, ns=1), arfcn, sub))
        out.append(sd(synth.iframe(bytes([0x06, 0x0D, 0x00]), ns=2), arfcn, sub))
    else:
        out.append(sd(synth.iframe(bytes([0x05, 0x04, cause])), arfcn, sub))
        out.append(sd(synth.iframe(bytes([0x06, 0x0D, 0x00]), ns=1), arfcn, sub))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=root / "docs" / "dashboard.svg")
    args = ap.parse_args()

    tracker = Tracker(PlmnDB.load())
    dash = Dashboard(tracker, title="imsi-catcher-ng")
    tracker.on_event = dash.event
    dash.status = "rx 938.4 MHz (ARFCN 17)"
    dec = Decoder()
    now = time.time()
    t = now - 240
    cells = [(17, 2001, -51), (975, 2002, -63), (52, 2104, -77)]
    for arfcn, ci, dbm in cells:
        tracker.process(t, dec.decode(si3(arfcn, 100 if arfcn != 52 else 101, ci, dbm)))
        tracker.process(t, dec.decode(si2(arfcn, [17, 23, 38, 52, 61, 70, 84, 101])))
    for i in range(60):
        t += 4
        arfcn = rng.choice([17, 17, 17, 975, 52])
        tracker.process(t, dec.decode(si3(arfcn, 100 if arfcn != 52 else 101,
                                          dict((a, c) for a, c, _ in cells)[arfcn],
                                          dict((a, d) for a, _, d in cells)[arfcn] + rng.randrange(-2, 3))))
        roll = rng.random()
        if roll < 0.45:
            tracker.process(t, dec.decode(paging(arfcn, synth.mi_tmsi(rng.randbytes(4)))))
        elif roll < 0.55:
            tracker.process(t, dec.decode(paging(arfcn, synth.mi_imsi(imsi()))))
        else:
            if rng.random() < 0.6:
                value = imsi()
                ident, accept = synth.mi_imsi(value), value.startswith("00101") or rng.random() < 0.3
            else:
                ident, accept = synth.mi_tmsi(rng.randbytes(4)), True
            for pkt in session(arfcn, rng.randrange(8), ident, accept=accept, cause=rng.choice([13, 11, 2])):
                t += 0.2
                tracker.process(t, dec.decode(pkt))
    tracker.housekeeping(now)

    console = Console(record=True, width=150, height=46, force_terminal=True, color_system="truecolor",
                      file=io.StringIO())
    console.print(dash.render())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(console.export_svg(title="imsi-catcher live --arfcn 17"))
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
