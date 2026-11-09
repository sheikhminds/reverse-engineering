#!/usr/bin/env python3
# Copyright (c) 2026 Likhon Sheikh <https://github.com/sheikhminds>
# SPDX-License-Identifier: MIT
"""Compare two files byte by byte and list the changed regions (standard library only).

The workhorse of differential analysis: change one thing in the source application,
save both versions, and see which bytes moved.

Usage:
    hexdiff.py A B [--gap N] [--context N] [--max-regions N]

Differences separated by --gap or fewer unchanged bytes are merged (default 2). If the files differ in length
the common prefix is compared and the length difference is reported, along with a
hint when the tail looks like a shifted copy (an insertion or deletion).
"""
import argparse


def regions(a, b, gap):
    n = min(len(a), len(b))
    out, start, last = [], None, None
    for i in range(n):
        if a[i] != b[i]:
            if start is None:
                start = last = i
            elif i - last > gap:
                out.append((start, last + 1))
                start = i
            last = i
    if start is not None:
        out.append((start, last + 1))
    return out


def fmt(data, lo, hi):
    return data[lo:hi].hex(" ") if hi > lo else "(none)"


def as_ints(old, new):
    """If a region is 1-8 bytes, show it as integers in both byte orders."""
    if not 1 <= len(old) == len(new) <= 8:
        return ""
    parts = []
    for order in ("little", "big"):
        o, n = int.from_bytes(old, order), int.from_bytes(new, order)
        parts.append(f"{order}: {o} -> {n} (delta {n - o:+d})")
    return "; ".join(parts)


def detect_shift(a, b):
    """Look for the longer file's tail equal to the shorter file's tail (insertion/deletion)."""
    short, long_ = (a, b) if len(a) <= len(b) else (b, a)
    k = len(short)
    for tail in (min(64, k), min(32, k), min(16, k)):
        if tail < 8:
            continue
        if long_.endswith(short[-tail:]):
            return (f"the last {tail} bytes of both files match, which suggests data was inserted "
                    f"or removed earlier in the file rather than rewritten")
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--gap", type=int, default=2, help="merge differences closer than this many bytes")
    ap.add_argument("--context", type=int, default=4, help="bytes of context shown around each region")
    ap.add_argument("--max-regions", type=int, default=60)
    args = ap.parse_args()

    a = open(args.a, "rb").read()
    b = open(args.b, "rb").read()
    print(f"A: {args.a} ({len(a)} bytes)\nB: {args.b} ({len(b)} bytes)")
    if len(a) != len(b):
        print(f"Length differs by {len(b) - len(a):+d} bytes.")
        hint = detect_shift(a, b)
        if hint:
            print("Note:", hint + ".")
    regs = regions(a, b, args.gap)
    n = min(len(a), len(b))
    changed = sum(1 for i in range(n) if a[i] != b[i])
    print(f"Compared first {n} bytes: {changed} differ ({changed / n * 100 if n else 0:.1f}%) in {len(regs)} region(s).")
    if n and changed / n > 0.4:
        print("Most bytes differ: this suggests compression, encryption, or a heavy shift rather than a small field change.")
    for lo, hi in regs[:args.max_regions]:
        c_lo, c_hi = max(0, lo - args.context), min(n, hi + args.context)
        print(f"\n@ {lo:#x}..{hi:#x} ({hi - lo} byte{'s' if hi - lo != 1 else ''})")
        print(f"  A: {fmt(a, lo, hi)}")
        print(f"  B: {fmt(b, lo, hi)}")
        iv = as_ints(a[lo:hi], b[lo:hi])
        if iv:
            print(f"  as integers - {iv}")
        print(f"  context A: {fmt(a, c_lo, lo)} [{fmt(a, lo, hi)}] {fmt(a, hi, c_hi)}")
    if len(regs) > args.max_regions:
        print(f"\n... {len(regs) - args.max_regions} more region(s) not shown (raise --max-regions)")
    if len(a) != len(b):
        longer, name = (a, "A") if len(a) > len(b) else (b, "B")
        print(f"\nExtra bytes at the end of {name} (from {n:#x}): {fmt(longer, n, min(len(longer), n + 32))}"
              f"{' ...' if len(longer) > n + 32 else ''}")


if __name__ == "__main__":
    import signal
    if hasattr(signal, "SIGPIPE"):  # not available on Windows
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)  # quiet exit when piped to head/less
    main()
