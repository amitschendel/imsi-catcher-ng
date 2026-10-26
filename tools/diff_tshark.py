#!/usr/bin/env python3
"""Cross-check the decoder against Wireshark's dissectors, frame by frame.

Usage: diff_tshark.py capture.pcap [--details]

Prints per-field agreement counts. Identity values are only shown with
--details, so the default output is safe to paste into bug reports.
"""

from __future__ import annotations

import argparse
import collections
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from imsicatcher.decoder import Decoder  # noqa: E402
from imsicatcher.sources import read_capture  # noqa: E402

FIELDS = [
    "frame.number",
    "e212.imsi",
    "3gpp.tmsi",
    "gsm_a.tmsi",
    "gsm_a.imei",
    "gsm_a.imeisv",
    "e212.lai.mcc",
    "e212.lai.mnc",
    "gsm_a.lac",
    "gsm_a.bssmap.cell_ci",
    "gsm_a.rr.timing_adv",
    "gsm_a.rr.ra",
    "gsm_a.rr.T1prim",
    "gsm_a.rr.T3",
    "gsm_a.rr.T2",
    "gsm_a.rr.algorithm_identifier",
    "gsm_a.rr.RRcause",
    "gsm_a.dtap.rej_cause",
    "gsm_a.rr.ccch_conf",
    "gsm_a.rr.bs_pa_mfrms",
    "gsm_a.rr.bs_ag_blks_res",
    "gsm_a.rr.t3212",
    "gsm_a.rr.neci",
    "gsm_a.rr.rxlev_access_min",
    "gsm_a.rr.max_retrans",
    "gsm_a.rr.tx_integer",
    "gsm_a.rr.cell_barr_access",
    "gsm_a.rr.page_mode",
    "gsm_a.rr.radio_link_timeout",
    "gsm_a.dtap.text_string",
    "gsm_a.dtap.type_of_identity",
    "gsm_a.rr.fdd_uarfcn",
    "_ws.col.Info",
]
SENSITIVE = {"e212.imsi", "3gpp.tmsi", "gsm_a.imei", "gsm_a.imeisv"}


def tshark_rows(pcap: str) -> dict[int, dict[str, list[str]]]:
    cmd = ["tshark", "-r", pcap, "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a",
           "-E", "aggregator=|"]
    for f in FIELDS:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    rows = {}
    for line in out.splitlines():
        cols = line.split("\t")
        cols += [""] * (len(FIELDS) - len(cols))
        rec = {f: [v for v in c.split("|") if v] for f, c in zip(FIELDS, cols)}
        rows[int(rec["frame.number"][0])] = rec
    return rows


# Wireshark cuts item labels at 240 characters, so long ARFCN lists lose their tail.
LABEL_LIMIT = 235


def tshark_arfcn_lists(pcap: str) -> dict[int, list[tuple[list[int], bool]]]:
    """Per frame: (ARFCNs, truncated) for each "List of ARFCNs" label."""
    out = subprocess.run(["tshark", "-r", pcap, "-V"], capture_output=True, text=True, check=True).stdout
    lists: dict[int, list[tuple[list[int], bool]]] = collections.defaultdict(list)
    frame = 0
    for line in out.splitlines():
        m = re.match(r"^Frame (\d+):", line)
        if m:
            frame = int(m.group(1))
            continue
        m = re.search(r"List of ARFCNs = ?([\d ]*)", line)
        if m:
            truncated = len(line.strip()) >= LABEL_LIMIT
            nums = m.group(1).split()
            if truncated and nums:
                nums = nums[:-1]  # the last number may itself be cut short
            lists[frame].append((sorted(int(x) for x in nums), truncated))
    return lists


def ours(pcap: str):
    dec = Decoder()
    for n, (_ts, dgram) in enumerate(read_capture(pcap, ports=None), start=1):
        yield n, dec.decode(dgram)


def walk(obj):
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk(v)


def our_values(d) -> dict[str, list]:
    v: dict[str, list] = collections.defaultdict(list)
    if d is None:
        return v
    for msg in d.messages:
        for node in walk(msg):
            kind, val = node.get("kind"), node.get("value")
            if kind == "imsi":
                v["e212.imsi"].append(val)
            elif kind == "tmsi":
                v["3gpp.tmsi"].append(int(val, 16))
            elif kind == "imei":
                v["gsm_a.imei"].append(val)
            elif kind == "imeisv":
                v["gsm_a.imeisv"].append(val)
            if node.get("deleted"):
                v["e212.lai.mcc"].append("deleted")
                v["e212.lai.mnc"].append("deleted")
            if node.get("mcc") is not None and "lac" in node:
                v["e212.lai.mcc"].append(int(node["mcc"]))
                v["e212.lai.mnc"].append(int(node["mnc"]))
            if "lac" in node:
                v["gsm_a.lac"].append(node["lac"])
            if "cell_id" in node:
                v["gsm_a.bssmap.cell_ci"].append(node["cell_id"])
            if "ta" in node and "distance_m" in node:
                v["gsm_a.rr.timing_adv"].append(node["ta"])
            if "fn_mod_42432" in node:
                v["gsm_a.rr.ra"].append(node["ra"])
                v["gsm_a.rr.T1prim"].append(node["t1"])
                v["gsm_a.rr.T3"].append(node["t3"])
                v["gsm_a.rr.T2"].append(node["t2"])
            if "ccch_conf" in node:
                v["gsm_a.rr.ccch_conf"].append(node["ccch_conf"])
                # tshark shows (raw + 2) in a 3-bit field, so 8 and 9 wrap to 0 and 1.
                v["gsm_a.rr.bs_pa_mfrms"].append(node["bs_pa_mfrms"] & 0x07)
                v["gsm_a.rr.bs_ag_blks_res"].append(node["bs_ag_blks_res"])
                v["gsm_a.rr.t3212"].append(node["t3212_minutes"] // 6)
            if "neci" in node:
                v["gsm_a.rr.neci"].append(int(node["neci"]))
                v["gsm_a.rr.rxlev_access_min"].append(node["rxlev_access_min_dbm"] + 110)
            if "max_retrans" in node:
                v["gsm_a.rr.max_retrans"].append([1, 2, 4, 7].index(node["max_retrans"]))
                v["gsm_a.rr.tx_integer"].append(
                    [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 16, 20, 25, 32, 50].index(node["tx_integer"]))
                v["gsm_a.rr.cell_barr_access"].append(int(node["cell_barred"]))
            if "radio_link_timeout" in node:
                v["gsm_a.rr.radio_link_timeout"].append(node["radio_link_timeout"] // 4 - 1)
            if "network_full_name" in node:
                v["gsm_a.dtap.text_string"].append(node["network_full_name"])
            if "network_short_name" in node:
                v["gsm_a.dtap.text_string"].append(node["network_short_name"])
        if msg.get("name") == "Ciphering Mode Command" and msg.get("ciphering"):
            v["gsm_a.rr.algorithm_identifier"].append(int(msg["algorithm"][3:]) - 1)
        if msg.get("name") == "Channel Release" and "cause_code" in msg:
            v["gsm_a.rr.RRcause"].append(msg["cause_code"])
        if msg.get("pd") == "MM" and "cause_code" in msg:
            v["gsm_a.dtap.rej_cause"].append(msg["cause_code"])
        for u in msg.get("utran_fdd", []) + msg.get("utran_tdd", []):
            v["gsm_a.rr.fdd_uarfcn"].append(u["uarfcn"])
        if "identity_type" in msg:
            v["gsm_a.dtap.type_of_identity"].append(
                {"IMSI": 1, "IMEI": 2, "IMEISV": 3, "TMSI": 4}.get(msg["identity_type"], -1))
        if "page_mode" in msg:
            v["gsm_a.rr.page_mode"].append(["normal", "extended", "reorganization", "same as before"]
                                           .index(msg["page_mode"]))
    return v


def norm(field: str, vals: list[str]) -> list:
    out = []
    for x in vals:
        if field == "3gpp.tmsi":
            out.append(int(x, 0))
        elif field in ("e212.imsi", "gsm_a.imei", "gsm_a.imeisv", "gsm_a.dtap.text_string"):
            out.append(x)
        elif field == "gsm_a.rr.timing_adv":
            out.append(int(x))
        else:
            try:
                out.append(int(x, 16) if x.startswith("0x") else int(x))
            except ValueError:
                out.append(x)
    return out


def _lists_match(ours: list[list[int]], theirs: list[tuple[list[int], bool]]) -> bool:
    if len(ours) != len(theirs):
        return False
    pending = list(ours)
    for t, truncated in theirs:
        for o in pending:
            if (set(t) <= set(o) and len(o) > len(t)) if truncated else o == t:
                pending.remove(o)
                break
        else:
            return False
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("--details", action="store_true", help="print mismatching values, including identities")
    args = ap.parse_args()

    ts = tshark_rows(args.pcap)
    lists = tshark_arfcn_lists(args.pcap)
    agree = collections.Counter()
    disagree = collections.Counter()
    examples = collections.defaultdict(list)
    names_missing = collections.Counter()

    for n, d in ours(args.pcap):
        row = ts.get(n)
        if row is None:
            continue
        mine = our_values(d)
        # Paging Type 2/3 TMSIs use gsm_a.tmsi, Mobile Identity TMSIs use 3gpp.tmsi.
        row["3gpp.tmsi"] = row["3gpp.tmsi"] + row.pop("gsm_a.tmsi", [])
        for f in FIELDS[1:-1]:
            if f == "gsm_a.tmsi":
                continue
            theirs = norm(f, row[f])
            if not theirs and not mine.get(f):
                continue
            if f == "gsm_a.dtap.text_string":
                theirs = [t for t in theirs if t]
            if f in ("e212.lai.mcc", "e212.lai.mnc") and "deleted" in mine.get(f, []):
                # tshark decodes the all-F "deleted" LAI as MCC 1665.
                theirs = ["deleted" if t == 1665 else t for t in theirs]
            if sorted(map(str, theirs)) == sorted(map(str, mine.get(f, []))):
                agree[f] += 1
            else:
                disagree[f] += 1
                if len(examples[f]) < 5:
                    if args.details or f not in SENSITIVE:
                        examples[f].append((n, theirs, mine.get(f, [])))
                    else:
                        examples[f].append((n, f"{len(theirs)} value(s)", f"{len(mine.get(f, []))} value(s)"))
        info = " ".join(row["_ws.col.Info"])
        for msg in (d.messages if d else []):
            if msg.get("name") and not msg["name"].startswith(("RR ", "MM ", "PD ")):
                if msg["name"].split(" (")[0] not in info and not msg.get("short_pd"):
                    names_missing[msg["name"]] += 1
        # ARFCN lists
        our_lists = []
        for msg in (d.messages if d else []):
            for key in ("cell_arfcns", "neighbours"):
                if key in msg:
                    our_lists.append(msg[key])
        their_lists = lists.get(n, [])
        if our_lists or their_lists:
            if _lists_match(our_lists, their_lists):
                agree["arfcn_lists"] += 1
            else:
                disagree["arfcn_lists"] += 1
                if len(examples["arfcn_lists"]) < 5:
                    examples["arfcn_lists"].append((n, their_lists, our_lists))

    width = max(len(f) for f in list(agree) + list(disagree) + ["field"])
    print(f"{'field':<{width}}  agree  disagree")
    for f in sorted(set(agree) | set(disagree)):
        print(f"{f:<{width}}  {agree[f]:5d}  {disagree[f]:8d}")
    if names_missing:
        print("\nmessage names not found in tshark Info column:", dict(names_missing))
    for f, ex in examples.items():
        print(f"\n{f} mismatches (frame, tshark, ours):")
        for e in ex:
            print("  ", e)
    return 1 if disagree else 0


if __name__ == "__main__":
    sys.exit(main())
