#!/usr/bin/env python3
"""Write a pcap of synthetic GSMTAP messages for cross-checking with tshark.

Usage: gen_vectors.py OUT.pcap [--count N] [--seed S]

Covers message types and encodings that a single real cell rarely shows:
paging types 2 and 3, assignment reject, all frequency list formats,
random rest octets. Pair it with diff_tshark.py.
"""

import argparse
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))
sys.path.insert(0, str(root / "tests"))

from imsicatcher.sources import PcapWriter  # noqa: E402
from synth import Gen  # noqa: E402

FORMATS = ("bitmap0", "1024", "512", "256", "128", "variable")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out")
    ap.add_argument("--count", type=int, default=300, help="messages per type (default 300)")
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()
    g = Gen(args.seed)
    w = PcapWriter(args.out)
    ts = 1_700_000_000.0
    builders = [g.paging1, g.paging2, g.paging3, g.ia, g.iax, g.iar, g.si3, g.lu_request,
                g.paging_response, g.cm_service_request, g.lu_accept, g.cipher_mode]
    builders += [lambda f=f: g.si1(f) for f in FORMATS] + [lambda f=f: g.si2(f) for f in FORMATS]
    n = 0
    for _ in range(args.count):
        for b in builders:
            dgram, _ = b()
            w.write(ts, dgram)
            ts += 0.001
            n += 1
    w.close()
    print(f"wrote {n} packets to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
