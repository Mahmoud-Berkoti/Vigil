#!/usr/bin/env python3
"""Generate a small synthetic MRT (BGP4MP_MESSAGE_AS4) file for `make
demo`: a victim prefix announced normally by its legitimate origin,
then hijacked by a different AS with a bogus path — modeled loosely on
the 2008 Pakistan Telecom / YouTube incident (a more-specific hijack;
here we do a same-prefix origin hijack, which is what the watchlist
detector is built to catch).

Usage: tools/gen_demo_mrt.py OUT.mrt
"""
import struct
import sys


def w8(buf, v):  buf.append(v & 0xFF)
def w16(buf, v): buf += struct.pack(">H", v & 0xFFFF)
def w32(buf, v): buf += struct.pack(">I", v & 0xFFFFFFFF)


def encode_prefix(prefix):
    addr, length = prefix.split("/")
    length = int(length)
    octets = [int(o) for o in addr.split(".")]
    nbytes = (length + 7) // 8
    return bytes([length]) + bytes(octets[:nbytes])


def build_update(prefix, as_path, next_hop):
    body = bytearray()
    w16(body, 0)  # withdrawn routes length

    attrs = bytearray()
    attrs += bytes([0x40, 1, 1, 0])  # ORIGIN IGP
    path_bytes = bytearray()
    path_bytes += bytes([2, len(as_path)])  # AS_SEQUENCE
    for asn in as_path:
        w32(path_bytes, asn)
    attrs += bytes([0x40, 2, len(path_bytes)]) + path_bytes
    nh = bytes(int(o) for o in next_hop.split("."))
    attrs += bytes([0x40, 3, 4]) + nh

    w16(body, len(attrs))
    body += attrs
    body += encode_prefix(prefix)

    msg = bytearray()
    msg += b"\xff" * 16
    total_len = 19 + len(body)
    w16(msg, total_len)
    msg += bytes([2])  # UPDATE
    msg += body
    return bytes(msg)


def bgp4mp_record(ts, peer_as, peer_ip, msg):
    body = bytearray()
    w32(body, peer_as)
    w32(body, 65000)  # local AS
    w16(body, 0)      # ifindex
    w16(body, 1)      # AFI IPv4
    body += bytes(int(o) for o in peer_ip.split("."))
    body += bytes([203, 0, 113, 254])  # local ip
    body += msg

    hdr = bytearray()
    w32(hdr, ts)
    w16(hdr, 16)  # BGP4MP
    w16(hdr, 4)   # BGP4MP_MESSAGE_AS4
    w32(hdr, len(body))
    return bytes(hdr) + bytes(body)


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else "data/fixtures/demo-hijack.mrt"
    victim_prefix = "203.0.113.0/24"
    victim_asn = 64500
    attacker_asn = 64666

    records = bytearray()
    t = 1_700_000_000

    # legitimate baseline traffic: several peers see the real origin
    for i, (peer_asn, peer_ip) in enumerate([
        (6939, "192.0.2.1"), (3356, "192.0.2.2"), (1299, "192.0.2.3"),
    ]):
        msg = build_update(victim_prefix, [peer_asn, victim_asn], "192.0.2.1")
        records += bgp4mp_record(t + i, peer_asn, peer_ip, msg)

    # some unrelated clean traffic for realism
    for i, pfx in enumerate(["198.51.100.0/24", "192.0.2.128/25"]):
        msg = build_update(pfx, [6939, 65001 + i], "192.0.2.1")
        records += bgp4mp_record(t + 10 + i, 6939, "192.0.2.1", msg)

    # the hijack: a different origin AS announces the victim prefix
    hijack_msg = build_update(victim_prefix, [4200000000, attacker_asn], "198.51.100.9")
    records += bgp4mp_record(t + 20, 4200000000, "198.51.100.9", hijack_msg)

    with open(out_path, "wb") as f:
        f.write(records)
    print(f"wrote {out_path}: victim={victim_prefix} legit_origin=AS{victim_asn} "
          f"attacker_origin=AS{attacker_asn}")


if __name__ == "__main__":
    main()
