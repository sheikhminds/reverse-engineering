#!/usr/bin/env python3
"""Show how the bytes at an offset read as every plausible type (standard library only).

Helps decide what a field is: integers in both byte orders, floats, timestamps,
length-prefixed or null-terminated strings, UTF-16 text, varints.

Usage:
    probe.py FILE OFFSET [--count N]      # OFFSET accepts decimal or 0x hex
    probe.py FILE OFFSET --hex "de ad be ef"   # probe literal bytes instead of a file
"""
import argparse
import datetime
import math
import struct


def plausible_ts(v):
    for scale, label in ((1, "unix s"), (1000, "unix ms")):
        try:
            secs = v / scale
            if 946684800 <= secs <= 2208988800:  # 2000..2040
                return f"{label}: {datetime.datetime.fromtimestamp(secs, datetime.UTC):%Y-%m-%d %H:%M:%S}Z"
        except (OverflowError, OSError, ValueError):
            pass
    if 1.2e17 <= v <= 1.4e17:
        try:
            dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=v / 10)
            return f"FILETIME: {dt:%Y-%m-%d %H:%M:%S}"
        except OverflowError:
            pass
    return ""


def good_float(x):
    return not (math.isnan(x) or math.isinf(x)) and (x == 0 or 1e-6 < abs(x) < 1e9)


def varint(data):
    val, shift = 0, 0
    for i, byte in enumerate(data[:10]):
        val |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return val, i + 1
        shift += 7
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", help="file path (ignored with --hex)")
    ap.add_argument("offset", help="decimal or 0x-prefixed hex")
    ap.add_argument("--count", type=int, default=16, help="bytes to show in the hex preview")
    ap.add_argument("--hex", help="probe these literal bytes instead of reading a file")
    args = ap.parse_args()

    if args.hex:
        data, off = bytes.fromhex(args.hex.replace(" ", "")), 0
    else:
        off = int(args.offset, 0)
        data = open(args.file, "rb").read()
    window = data[off:]
    if not window:
        raise SystemExit("offset is past the end of the data")

    print(f"Offset {off:#x} ({off}); {len(window)} bytes available")
    print("Bytes:", window[:args.count].hex(" "))
    print("ASCII:", "".join(chr(b) if 32 <= b < 127 else "." for b in window[:args.count]))
    print()

    print("Integers")
    for size, name in ((1, "u8"), (2, "u16"), (4, "u32"), (8, "u64")):
        if len(window) < size:
            break
        for order, tag in (("little", "LE"), ("big", "BE")):
            u = int.from_bytes(window[:size], order)
            s = int.from_bytes(window[:size], order, signed=True)
            note = f"  signed {s}" if s != u else ""
            extra = plausible_ts(u) if size >= 4 else ""
            print(f"  {name} {tag}: {u}{note}  ({u:#x}){'  <- ' + extra if extra else ''}")
            if size == 1:
                break

    print("\nFloats")
    for size, code, name in ((4, "f", "f32"), (8, "d", "f64")):
        if len(window) < size:
            break
        for order, tag in (("<", "LE"), (">", "BE")):
            x = struct.unpack(order + code, window[:size])[0]
            mark = "  <- plausible" if good_float(x) else ""
            print(f"  {name} {tag}: {x!r}{mark}")

    print("\nScaled fixed-point guesses (u16/i16 / 10 or 100)")
    if len(window) >= 2:
        for order, tag in (("<", "LE"), (">", "BE")):
            u, = struct.unpack(order + "H", window[:2])
            i, = struct.unpack(order + "h", window[:2])
            print(f"  {tag}: u16/10={u / 10}  u16/100={u / 100}  i16/10={i / 10}  i16/100={i / 100}")

    print("\nStrings")
    n = window[0]
    if 0 < n < len(window) and all(32 <= c < 127 for c in window[1:1 + n]):
        print(f"  u8 length-prefixed ({n}): {window[1:1 + n].decode('ascii')!r}")
    if len(window) >= 3:
        for order, tag in (("<", "LE"), (">", "BE")):
            n, = struct.unpack(order + "H", window[:2])
            if 0 < n < len(window) - 1 and all(32 <= c < 127 for c in window[2:2 + n]):
                print(f"  u16 {tag} length-prefixed ({n}): {window[2:2 + n].decode('ascii')!r}")
    end = window.find(b"\x00")
    if end > 0 and all(32 <= c < 127 for c in window[:end]):
        print(f"  null-terminated: {window[:end].decode('ascii')!r}")
    if len(window) >= 4 and window[1] == 0 and window[3] == 0 and 32 <= window[0] < 127:
        chars = []
        for i in range(0, len(window) - 1, 2):
            if window[i + 1] == 0 and 32 <= window[i] < 127:
                chars.append(chr(window[i]))
            else:
                break
        print(f"  UTF-16LE run: {''.join(chars)!r}")

    print("\nVarint (LEB128 / protobuf)")
    v = varint(window)
    if v:
        val, used = v
        zz = (val >> 1) ^ -(val & 1)
        print(f"  value {val} using {used} byte(s); zigzag-decoded {zz}")
        tag_field, wt = val >> 3, val & 7
        if 1 <= tag_field < 64 and wt in (0, 1, 2, 5):
            print(f"  as a protobuf tag: field {tag_field}, wire type {wt}")
    else:
        print("  not a valid varint")


if __name__ == "__main__":
    import signal
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)  # quiet exit when piped to head/less
    main()
