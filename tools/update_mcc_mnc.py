#!/usr/bin/env python3
"""Rebuild src/imsicatcher/data/mcc_mnc.json from Wikipedia's MCC/MNC lists.

Usage: update_mcc_mnc.py [--cache DIR] [--out PATH]

Downloads the raw wikitext of the six "Mobile network codes in ITU region"
pages plus "Mobile country code" (international and test codes), and parses
the MNC tables with the standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
import urllib.request
from datetime import date
from pathlib import Path

PAGES = [
    "Mobile_network_codes_in_ITU_region_2xx_(Europe)",
    "Mobile_network_codes_in_ITU_region_3xx_(North_America)",
    "Mobile_network_codes_in_ITU_region_4xx_(Asia)",
    "Mobile_network_codes_in_ITU_region_5xx_(Oceania)",
    "Mobile_network_codes_in_ITU_region_6xx_(Africa)",
    "Mobile_network_codes_in_ITU_region_7xx_(South_America)",
    "Mobile_country_code",
]
UA = "imsi-catcher-ng/1.0 (MCC/MNC table builder)"
DASH = "\u2013"  # separator in "Country \u2013 ISO" headings


def fetch(title: str, cache: Path | None) -> str:
    if cache:
        p = cache / f"{title}.txt"
        if p.exists():
            return p.read_text(encoding="utf-8")
    url = "https://en.wikipedia.org/w/index.php?" + urllib.parse.urlencode({"title": title, "action": "raw"})
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as r:
        text = r.read().decode("utf-8")
    if cache:
        cache.mkdir(parents=True, exist_ok=True)
        (cache / f"{title}.txt").write_text(text, encoding="utf-8")
    return text


_REF = re.compile(r"<ref[^>/]*/>|<ref[^>]*>.*?</ref>", re.S)
_TEMPLATE = re.compile(r"\{\{[^{}]*\}\}")
_LINK = re.compile(r"\[\[(?:[^|\]]*\|)?([^\]]*)\]\]")
_EXTLINK = re.compile(r"\[(?:https?:)?//\S+\s+([^\]]*)\]|\[(?:https?:)?//\S+\]")
_TAG = re.compile(r"<[^>]+>")
_CELL_ATTR = re.compile(r"^\s*(?:[a-z-]+\s*=\s*(?:\"[^\"]*\"|[^|\s]*)\s*)+\|(?!\|)")


_INTERWIKI = re.compile(r"\[\[:[a-z-]{2,12}:[^\]]*\]\]|\[ ?[a-z]{2,3} ?\]")


def clean(text: str) -> str:
    text = _REF.sub("", text)
    text = _INTERWIKI.sub("", text)
    text = _LINK.sub(r"\1", text)
    for _ in range(3):
        text = _TEMPLATE.sub(lambda m: _template_text(m.group(0)), text)
    text = _EXTLINK.sub(lambda m: m.group(1) or "", text)
    text = _TAG.sub("", text)
    text = text.replace("&nbsp;", " ").replace("&amp;", "&").replace("'''", "").replace("''", "")
    return " ".join(text.split()).strip()


def _template_text(t: str) -> str:
    inner = t[2:-2]
    parts = inner.split("|")
    name = parts[0].strip().lower()
    if name in ("sort", "sortname", "nowrap", "nobr") and len(parts) > 1:
        return parts[-1]
    if name in ("flagu", "flag", "flagcountry", "toc tab") and len(parts) > 1:
        return parts[1]
    return ""


def parse_heading(line: str) -> tuple[str, str] | None:
    m = re.match(r"^=+\s*(.*?)\s*=+\s*$", line)
    if not m:
        return None
    text = clean(m.group(1))
    if f" {DASH} " in text:
        country, iso = text.rsplit(f" {DASH} ", 1)
    elif " - " in text:
        country, iso = text.rsplit(" - ", 1)
    else:
        country, iso = text, ""
    return country.strip(), iso.strip()


def parse_rows(text: str):
    """Yield (country, iso, cells) for each row of an MNC table."""
    country, iso = "", ""
    in_table = False
    cells: list[str] = []

    def flush():
        if len(cells) >= 2:
            yield country, iso, cells

    for raw in text.splitlines():
        line = raw.strip()
        h = parse_heading(line)
        if h and not in_table:
            country, iso = h
            continue
        if line.startswith("{|"):
            in_table = True
            cells = []
            continue
        if not in_table:
            continue
        if line.startswith("|}"):
            yield from flush()
            in_table = False
            cells = []
            continue
        if line.startswith("|-"):
            yield from flush()
            cells = []
            continue
        if line.startswith("!") or line.startswith("|+"):
            continue
        if line.startswith("|"):
            for c in line[1:].split("||"):
                # Drop cell attributes such as 'rowspan=2 | value'.
                c = _CELL_ATTR.sub("", c, count=1)
                cells.append(clean(c))


def mcc_countries(text: str) -> dict[str, list[tuple[str, str]]]:
    """Country rows of the MCC table on the "Mobile country code" page."""
    out: dict[str, list[tuple[str, str]]] = {}
    for _country, _iso, cells in parse_rows(text):
        if len(cells) >= 3 and re.fullmatch(r"\d{3}", cells[0]) and not cells[1].isdigit():
            out.setdefault(cells[0], []).append((cells[1], cells[2]))
    return out


def build(cache: Path | None) -> dict:
    out: dict[str, dict] = {}
    countries: dict[str, list[tuple[str, str]]] = {}
    candidates: dict[tuple[str, str], list[list[str]]] = {}
    for title in PAGES:
        text = fetch(title, cache)
        if title == "Mobile_country_code":
            countries = mcc_countries(text)
        for country, iso, cells in parse_rows(text):
            mcc, mnc = cells[0], cells[1]
            if not re.fullmatch(r"\d{3}", mcc) or not re.fullmatch(r"\d{2,3}", mnc):
                continue
            entry = out.setdefault(mcc, {"country": "", "iso": "", "mnc": {}})
            brand = cells[2] if len(cells) > 2 else ""
            operator = cells[3] if len(cells) > 3 else ""
            status = cells[4] if len(cells) > 4 else ""
            bands = cells[5] if len(cells) > 5 else ""
            # A network can be listed under several countries (310-260 under Puerto Rico
            # and the US); keep every candidate and choose once the MCC's country is known.
            candidates.setdefault((mcc, mnc), []).append([brand, operator, status, bands, country, iso])
            entry["mnc"].setdefault(mnc, candidates[(mcc, mnc)][0])
    for mcc, entry in out.items():
        # Shared MCCs (310 for the US and its territories): use the country most
        # of the networks belong to, falling back to the MCC table.
        counts: dict[tuple[str, str], int] = {}
        for net in entry["mnc"].values():
            if net[4]:
                counts[(net[4], net[5])] = counts.get((net[4], net[5]), 0) + 1
        if counts:
            entry["country"], entry["iso"] = max(counts, key=counts.get)
        elif countries.get(mcc):
            entry["country"], entry["iso"] = countries[mcc][0]
        for mnc in list(entry["mnc"]):
            options = candidates[(mcc, mnc)]
            net = next((o for o in options if o[4] == entry["country"]), options[0])
            if net[4] == entry["country"]:
                net = net[:4]
            entry["mnc"][mnc] = net
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cache", type=Path, help="directory for downloaded wikitext (reused when present)")
    ap.add_argument("--out", type=Path,
                    default=Path(__file__).resolve().parents[1] / "src/imsicatcher/data/mcc_mnc.json")
    args = ap.parse_args()
    data = build(args.cache)
    doc = {
        "source": "https://en.wikipedia.org/wiki/Mobile_country_code (CC BY-SA 4.0)",
        "generated": date.today().isoformat(),
        "fields": ["brand", "operator", "status", "bands", "country if not the MCC's", "iso"],
        "mcc": dict(sorted(data.items())),
    }
    args.out.write_text(json.dumps(doc, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    n = sum(len(v["mnc"]) for v in data.values())
    print(f"wrote {args.out}: {len(data)} MCCs, {n} networks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
