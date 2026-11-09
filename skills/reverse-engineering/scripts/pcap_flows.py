#!/usr/bin/env python3
# Copyright (c) 2026 Likhon Sheikh <https://github.com/sheikhminds>
# SPDX-License-Identifier: MIT
"""Summarize a classic .pcap file and dump one flow's payloads (standard library only).

Handles Ethernet, Linux cooked (SLL) and raw-IP link types, IPv4 and IPv6, TCP and UDP.
For .pcapng files convert first:  editcap -F pcap in.pcapng out.pcap   (or tshark -F pcap).

Usage:
    pcap_flows.py CAP.pcap                    # list flows
    pcap_flows.py CAP.pcap --flow 2           # dump payloads of flow 2, by direction
    pcap_flows.py CAP.pcap --flow 2 --raw out       # also write out.A-B.bin and out.B-A.bin (reassembled bytes per direction)

Reassembly is by sequence number for TCP (retransmissions and overlaps are dropped);
out-of-order segments are placed by sequence number, gaps are reported.
"""
import argparse
import socket
import struct
import sys
from collections import OrderedDict


def read_pcap(path):
    with open(path, "rb") as f:
        head = f.read(24)
        if len(head) < 24:
            raise SystemExit("file too short for a pcap header")
        magic = head[:4]
        if magic == b"\x0a\x0d\x0d\x0a":
            raise SystemExit("this is pcapng; convert it first with: editcap -F pcap in.pcapng out.pcap")
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            end = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            end = ">"
        else:
            raise SystemExit("not a classic pcap file")
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        linktype = struct.unpack(end + "I", head[20:24])[0]
        pkts = []
        while True:
            h = f.read(16)
            if len(h) < 16:
                break
            ts_s, ts_f, caplen, _ = struct.unpack(end + "IIII", h)
            pkts.append((ts_s + ts_f / (1e9 if nano else 1e6), f.read(caplen)))
    return linktype, pkts


def l3_offset(linktype, pkt):
    """Return (offset of IP header, ethertype-ish) or None."""
    if linktype == 1 and len(pkt) >= 14:                       # Ethernet
        et, off = struct.unpack("!H", pkt[12:14])[0], 14
        while et in (0x8100, 0x88A8) and len(pkt) >= off + 4:  # VLAN tags
            et, off = struct.unpack("!H", pkt[off + 2:off + 4])[0], off + 4
        return off, et
    if linktype == 113 and len(pkt) >= 16:                     # Linux cooked
        return 16, struct.unpack("!H", pkt[14:16])[0]
    if linktype in (101, 12, 14) and pkt:                      # raw IP
        return 0, 0x0800 if pkt[0] >> 4 == 4 else 0x86DD
    return None


def parse(pkt, linktype):
    loc = l3_offset(linktype, pkt)
    if not loc:
        return None
    off, et = loc
    if et == 0x0800 and len(pkt) >= off + 20:
        ihl = (pkt[off] & 0x0F) * 4
        proto = pkt[off + 9]
        src, dst = socket.inet_ntoa(pkt[off + 12:off + 16]), socket.inet_ntoa(pkt[off + 16:off + 20])
        total = struct.unpack("!H", pkt[off + 2:off + 4])[0]
        l4, end = off + ihl, min(len(pkt), off + total) if total else len(pkt)
    elif et == 0x86DD and len(pkt) >= off + 40:
        proto = pkt[off + 6]
        src = socket.inet_ntop(socket.AF_INET6, pkt[off + 8:off + 24])
        dst = socket.inet_ntop(socket.AF_INET6, pkt[off + 24:off + 40])
        l4, end = off + 40, len(pkt)
    else:
        return None
    if proto == 6 and len(pkt) >= l4 + 20:
        sp, dp, seq, ack, doff_flags = struct.unpack("!HHIIH", pkt[l4:l4 + 14])
        hl = (doff_flags >> 12) * 4
        return ("tcp", src, sp, dst, dp, seq, doff_flags & 0x3F, pkt[l4 + hl:end])
    if proto == 17 and len(pkt) >= l4 + 8:
        sp, dp = struct.unpack("!HH", pkt[l4:l4 + 4])
        return ("udp", src, sp, dst, dp, 0, 0, pkt[l4 + 8:end])
    return None


def build_flows(linktype, pkts):
    flows = OrderedDict()
    for ts, pkt in pkts:
        p = parse(pkt, linktype)
        if not p:
            continue
        proto, src, sp, dst, dp, seq, flags, payload = p
        a, b = (src, sp), (dst, dp)
        key = (proto,) + (min(a, b), max(a, b))
        fl = flows.setdefault(key, {"proto": proto, "a": min(a, b), "b": max(a, b), "pkts": [], "first": ts})
        fl["pkts"].append({"ts": ts, "from": a, "seq": seq, "flags": flags, "data": payload})
    return list(flows.values())


def reassemble(flow, sender):
    """TCP: order by seq, drop duplicates. UDP: concatenate datagrams, remembering boundaries."""
    segs = [p for p in flow["pkts"] if p["from"] == sender and p["data"]]
    if flow["proto"] == "udp":
        return [(p["ts"], p["data"]) for p in segs], []
    syn = [p for p in flow["pkts"] if p["from"] == sender and p["flags"] & 0x02]
    base = syn[0]["seq"] + 1 if syn else (min(p["seq"] for p in segs) if segs else 0)
    out, gaps, nxt = [], [], base
    for p in sorted(segs, key=lambda p: (p["seq"] - base) & 0xFFFFFFFF):
        rel = (p["seq"] - nxt) & 0xFFFFFFFF
        data = p["data"]
        if rel >= 0x80000000:                      # starts before nxt: overlap or retransmit
            skip = (nxt - p["seq"]) & 0xFFFFFFFF
            if skip >= len(data):
                continue
            data = data[skip:]
        elif rel > 0:
            gaps.append((nxt, rel))
        out.append((p["ts"], data))
        nxt = (nxt + len(data) + (rel if 0 < rel < 0x80000000 else 0)) & 0xFFFFFFFF
    return out, gaps


def hexdump(data, indent="    "):
    for i in range(0, len(data), 16):
        row = data[i:i + 16]
        print(f"{indent}{i:04x}  {row.hex(' '):<47}  {''.join(chr(b) if 32 <= b < 127 else '.' for b in row)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("--flow", type=int, help="flow number to dump (from the listing)")
    ap.add_argument("--raw", help="write reassembled bytes to this path prefix (one file per direction)")
    ap.add_argument("--max-bytes", type=int, default=2048, help="max bytes of each segment to hexdump")
    args = ap.parse_args()

    linktype, pkts = read_pcap(args.pcap)
    flows = build_flows(linktype, pkts)
    if not flows:
        raise SystemExit("no TCP/UDP flows found (check the link type or whether the capture is encrypted at L2)")

    if args.flow is None:
        print(f"{len(pkts)} packets, {len(flows)} flow(s), link type {linktype}")
        print(f"{'#':>3}  {'proto':<5} {'endpoint A':<24} {'endpoint B':<24} {'pkts':>5} {'A->B bytes':>11} {'B->A bytes':>11}")
        for i, fl in enumerate(flows):
            ab = sum(len(p["data"]) for p in fl["pkts"] if p["from"] == fl["a"])
            ba = sum(len(p["data"]) for p in fl["pkts"] if p["from"] == fl["b"])
            a, b = f"{fl['a'][0]}:{fl['a'][1]}", f"{fl['b'][0]}:{fl['b'][1]}"
            print(f"{i:>3}  {fl['proto']:<5} {a:<24} {b:<24} {len(fl['pkts']):>5} {ab:>11} {ba:>11}")
        print("\nRe-run with --flow N to dump a flow's payloads.")
        return

    if not 0 <= args.flow < len(flows):
        raise SystemExit(f"flow must be between 0 and {len(flows) - 1}")
    fl = flows[args.flow]
    print(f"Flow {args.flow}: {fl['proto']} {fl['a'][0]}:{fl['a'][1]} <-> {fl['b'][0]}:{fl['b'][1]}")
    t0 = fl["first"]
    for p in fl["pkts"]:
        if not p["data"]:
            continue
        arrow = "A->B" if p["from"] == fl["a"] else "B->A"
        print(f"\n[{p['ts'] - t0:8.3f}s] {arrow} {len(p['data'])} bytes")
        hexdump(p["data"][:args.max_bytes])
        if len(p["data"]) > args.max_bytes:
            print(f"    ... {len(p['data']) - args.max_bytes} more bytes")
    for tag, sender in (("A->B", fl["a"]), ("B->A", fl["b"])):
        segs, gaps = reassemble(fl, sender)
        total = b"".join(d for _, d in segs)
        print(f"\nReassembled {tag}: {len(total)} bytes in {len(segs)} segment(s)"
              + (f"; {len(gaps)} gap(s) (capture incomplete)" if gaps else ""))
        if args.raw:
            path = f"{args.raw}.{tag.replace('>', '')}.bin"
            with open(path, "wb") as f:
                f.write(total)
            print(f"  wrote {path}")


if __name__ == "__main__":
    import signal
    if hasattr(signal, "SIGPIPE"):  # not available on Windows
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)  # quiet exit when piped to head/less
    main()
