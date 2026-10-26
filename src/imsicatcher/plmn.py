"""MCC/MNC lookups and IMSI splitting."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources


@dataclass(frozen=True, slots=True)
class Network:
    mcc: str
    mnc: str
    country: str
    iso: str
    brand: str
    operator: str
    status: str
    bands: str

    @property
    def name(self) -> str:
        return self.brand or self.operator or f"{self.mcc}-{self.mnc}"


class PlmnDB:
    def __init__(self, data: dict) -> None:
        self._mcc = data.get("mcc", {})
        self._lengths: dict[str, frozenset[int]] = {
            mcc: frozenset(len(m) for m in e["mnc"]) for mcc, e in self._mcc.items()
        }

    @classmethod
    def load(cls, path: str | None = None) -> "PlmnDB":
        if path:
            with open(path, encoding="utf-8") as f:
                return cls(json.load(f))
        text = resources.files("imsicatcher").joinpath("data/mcc_mnc.json").read_text(encoding="utf-8")
        return cls(json.loads(text))

    def country(self, mcc: str) -> tuple[str, str]:
        e = self._mcc.get(mcc)
        return (e["country"], e["iso"]) if e else ("", "")

    def network(self, mcc: str, mnc: str) -> Network | None:
        e = self._mcc.get(mcc)
        if not e:
            return None
        row = e["mnc"].get(mnc)
        if row is None:
            return None
        country, iso = (row[4], row[5]) if len(row) > 4 else (e["country"], e["iso"])
        return Network(mcc, mnc, country, iso, row[0], row[1], row[2], row[3])

    def split_imsi(self, imsi: str, serving: tuple[str, str] | None = None) -> tuple[str, str, str]:
        """Split an IMSI into (mcc, mnc, msin).

        The IMSI does not encode the MNC length. The serving cell's PLMN is the
        best hint (its LAI encodes the length); otherwise the table decides,
        preferring a 3-digit match where the MCC uses both lengths.
        """
        mcc = imsi[:3]
        if serving and serving[0] == mcc and imsi[3:].startswith(serving[1]):
            n = len(serving[1])
            return mcc, imsi[3:3 + n], imsi[3 + n:]
        lengths = self._lengths.get(mcc, frozenset())
        nets = self._mcc.get(mcc, {}).get("mnc", {})
        if lengths == {3}:
            n = 3
        elif lengths == {2} or not lengths:
            n = 3 if mcc in _THREE_DIGIT_MCCS else 2
        elif imsi[3:6] in nets:
            n = 3
        elif imsi[3:5] in nets:
            n = 2
        else:
            n = 2
        return mcc, imsi[3:3 + n], imsi[3 + n:]


# MCCs that assign 3-digit MNCs, for MCCs missing from the table.
_THREE_DIGIT_MCCS = frozenset(
    "302 310 311 312 313 314 315 316 334 338 342 344 346 348 354 356 358 360 365 "
    "366 376 405 708 722 732".split()
)


@lru_cache(maxsize=1)
def default_db() -> PlmnDB:
    return PlmnDB.load()
