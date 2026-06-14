#!/usr/bin/env python3
"""Carve the first N records out of an MRT file (record-aligned),
to produce a small checked-in test fixture from a real dump.

Usage: tools/carve_mrt.py IN.mrt OUT.mrt N
"""
import struct
import sys


def main():
    src, dst, count = sys.argv[1], sys.argv[2], int(sys.argv[3])
    with open(src, "rb") as f, open(dst, "wb") as out:
        for _ in range(count):
            hdr = f.read(12)
            if len(hdr) < 12:
                break
            _, _, _, length = struct.unpack(">IHHI", hdr)
            body = f.read(length)
            if len(body) < length:
                break
            out.write(hdr + body)


if __name__ == "__main__":
    main()
