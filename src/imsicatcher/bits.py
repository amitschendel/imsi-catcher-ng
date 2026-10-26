"""Bit readers for CSN.1 rest octets and packed fields."""

from __future__ import annotations

# CSN.1 spare padding on GSM downlink is the repeating octet 0x2B.
PAD_OCTET = 0x2B


class BitsExhausted(Exception):
    pass


class BitReader:
    __slots__ = ("data", "pos", "end")

    def __init__(self, data: bytes, start_bit: int = 0, end_bit: int | None = None) -> None:
        self.data = data
        self.pos = start_bit
        self.end = len(data) * 8 if end_bit is None else end_bit

    @property
    def remaining(self) -> int:
        return self.end - self.pos

    def bit(self) -> int:
        if self.pos >= self.end:
            raise BitsExhausted
        p = self.pos
        self.pos = p + 1
        return (self.data[p >> 3] >> (7 - (p & 7))) & 1

    def bits(self, n: int) -> int:
        if self.pos + n > self.end:
            raise BitsExhausted
        v = 0
        for _ in range(n):
            v = (v << 1) | self.bit()
        return v

    def lh(self) -> int:
        """Read one L/H bit: 0 for L (matches padding), 1 for H."""
        p = self.pos
        b = self.bit()
        pad = (PAD_OCTET >> (7 - (p & 7))) & 1
        return b ^ pad
