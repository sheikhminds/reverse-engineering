#!/usr/bin/env python3
"""First-look triage of an unknown file (standard library only).

Reports: size and hashes, identified type, a hex preview, an entropy profile,
embedded signatures at non-zero offsets, interesting strings, and a summary of
ELF / PE headers when present.

Usage:
    triage.py FILE [--json] [--blocks N] [--min-len N] [--strings N]
"""
import argparse
import hashlib
import json
import math
import re
import shutil
import struct
import subprocess
import sys

# (signature bytes, offset, description)
SIGNATURES = [
    (b"\x7fELF", 0, "ELF executable/object"),
    (b"MZ", 0, "DOS/PE executable (MZ)"),
    (b"\xfe\xed\xfa\xce", 0, "Mach-O 32-bit (BE)"),
    (b"\xce\xfa\xed\xfe", 0, "Mach-O 32-bit (LE)"),
    (b"\xfe\xed\xfa\xcf", 0, "Mach-O 64-bit (BE)"),
    (b"\xcf\xfa\xed\xfe", 0, "Mach-O 64-bit (LE)"),
    (b"\xca\xfe\xba\xbe", 0, "Java class or Mach-O universal binary"),
    (b"\x00asm", 0, "WebAssembly module"),
    (b"dex\n", 0, "Android DEX"),
    (b"PK\x03\x04", 0, "ZIP archive (also jar/apk/docx/xlsx)"),
    (b"\x1f\x8b\x08", 0, "gzip stream"),
    (b"BZh", 0, "bzip2 stream"),
    (b"\xfd7zXZ\x00", 0, "xz stream"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7-Zip archive"),
    (b"Rar!\x1a\x07", 0, "RAR archive"),
    (b"\x28\xb5\x2f\xfd", 0, "Zstandard stream"),
    (b"\x04\x22\x4d\x18", 0, "LZ4 frame"),
    (b"%PDF-", 0, "PDF document"),
    (b"SQLite format 3\x00", 0, "SQLite database"),
    (b"\x89PNG\r\n\x1a\n", 0, "PNG image"),
    (b"\xff\xd8\xff", 0, "JPEG image"),
    (b"GIF8", 0, "GIF image"),
    (b"RIFF", 0, "RIFF container (WAV/AVI/WebP)"),
    (b"OggS", 0, "Ogg container"),
    (b"\xd4\xc3\xb2\xa1", 0, "pcap (little-endian)"),
    (b"\xa1\xb2\xc3\xd4", 0, "pcap (big-endian)"),
    (b"\x0a\x0d\x0d\x0a", 0, "pcapng"),
    (b"hsqs", 0, "SquashFS (little-endian)"),
    (b"UBI#", 0, "UBI image"),
    (b"UPX!", 0, "UPX packer marker"),
    (b"ustar", 257, "tar archive"),
    (b"<?xml", 0, "XML text"),
    (b"{", 0, "possibly JSON text"),
]

# Signatures worth searching for inside the file (skip very short/noisy ones)
EMBEDDED = [
    (b"PK\x03\x04", "ZIP local header"),
    (b"\x1f\x8b\x08", "gzip stream"),
    (b"\x78\x9c", "zlib stream (default compression)"),
    (b"\x78\xda", "zlib stream (best compression)"),
    (b"\x78\x01", "zlib stream (no/low compression)"),
    (b"BZh", "bzip2 stream"),
    (b"\xfd7zXZ\x00", "xz stream"),
    (b"\x28\xb5\x2f\xfd", "Zstandard stream"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"hsqs", "SquashFS"),
    (b"\x7fELF", "ELF"),
    (b"%PDF-", "PDF"),
]

URL_RE = re.compile(rb"https?://[\x21-\x7e]{4,}")
EMAIL_RE = re.compile(rb"[\w.+-]+@[\w-]+\.[\w.-]+")
IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PATH_RE = re.compile(rb"(?:/[\w.-]+){2,}|[A-Za-z]:\\[\w\\. -]+")
VERSION_RE = re.compile(rb"\bv?\d+\.\d+(?:\.\d+)+\b")
FORMAT_RE = re.compile(rb"%[-+ #0]*\d*(?:\.\d+)?(?:hh|h|ll|l|z|j|t)?[sdiuxXfcpo]")


def shannon(block):
    if not block:
        return 0.0
    counts = [0] * 256
    for b in block:
        counts[b] += 1
    n = len(block)
    return max(0.0, -sum(c / n * math.log2(c / n) for c in counts if c))


def identify(data):
    hits = []
    for sig, off, name in SIGNATURES:
        if data[off:off + len(sig)] == sig:
            hits.append(name)
    return hits


def entropy_profile(data, blocks):
    if not data:
        return []
    size = max(256, math.ceil(len(data) / blocks))
    prof = []
    for off in range(0, len(data), size):
        chunk = data[off:off + size]
        prof.append({"offset": off, "size": len(chunk), "entropy": round(shannon(chunk), 2)})
    return prof


def embedded_signatures(data, limit=40):
    found = []
    for sig, name in EMBEDDED:
        start = 1
        while len(found) < limit * 4:
            i = data.find(sig, start)
            if i < 0:
                break
            found.append({"offset": i, "what": name})
            start = i + 1
            if sum(1 for f in found if f["what"] == name) >= 8:
                break
    found.sort(key=lambda f: f["offset"])
    return found[:limit]


def extract_strings(data, min_len):
    ascii_re = re.compile(rb"[\x20-\x7e\t]{%d,}" % min_len)
    utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    out = [(m.start(), "ascii", m.group().decode("ascii")) for m in ascii_re.finditer(data)]
    out += [(m.start(), "utf16le", m.group().decode("utf-16le")) for m in utf16_re.finditer(data)]
    out.sort()
    return out


def interesting(data):
    found = {}
    for label, rx in [("urls", URL_RE), ("emails", EMAIL_RE), ("ip_addresses", IP_RE),
                      ("paths", PATH_RE), ("versions", VERSION_RE), ("format_strings", FORMAT_RE)]:
        vals = sorted({m.group().decode("latin-1") for m in rx.finditer(data)})
        if vals:
            found[label] = vals[:15]
    return found


ELF_MACHINES = {0x03: "x86", 0x3E: "x86-64", 0x28: "ARM", 0xB7: "AArch64", 0x08: "MIPS",
                0xF3: "RISC-V", 0x14: "PowerPC", 0x15: "PowerPC64", 0x02: "SPARC", 0x5E: "Xtensa"}
ELF_TYPES = {1: "relocatable", 2: "executable", 3: "shared object / PIE", 4: "core"}


def parse_elf(data):
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return None
    bits = {1: 32, 2: 64}.get(data[4], "?")
    endian = "<" if data[5] == 1 else ">"
    info = {"class": f"{bits}-bit", "endianness": "little" if data[5] == 1 else "big"}
    e_type, e_machine = struct.unpack_from(endian + "HH", data, 16)
    info["type"] = ELF_TYPES.get(e_type, hex(e_type))
    info["machine"] = ELF_MACHINES.get(e_machine, hex(e_machine))
    if bits == 64:
        info["entry"] = hex(struct.unpack_from(endian + "Q", data, 24)[0])
        shoff, = struct.unpack_from(endian + "Q", data, 40)
        shentsize, shnum, shstrndx = struct.unpack_from(endian + "HHH", data, 58)
    elif bits == 32:
        info["entry"] = hex(struct.unpack_from(endian + "I", data, 24)[0])
        shoff, = struct.unpack_from(endian + "I", data, 32)
        shentsize, shnum, shstrndx = struct.unpack_from(endian + "HHH", data, 46)
    else:
        return info
    sections = []
    try:
        if shoff and shnum:
            hdrs = []
            for i in range(shnum):
                o = shoff + i * shentsize
                if bits == 64:
                    name, typ, flags, addr, off, size = struct.unpack_from(endian + "IIQQQQ", data, o)
                else:
                    name, typ, flags, addr, off, size = struct.unpack_from(endian + "IIIIII", data, o)
                hdrs.append((name, typ, addr, off, size))
            stroff = hdrs[shstrndx][3]
            for name, typ, addr, off, size in hdrs:
                end = data.find(b"\x00", stroff + name)
                sections.append({"name": data[stroff + name:end].decode("latin-1"),
                                 "addr": hex(addr), "offset": off, "size": size})
            info["stripped"] = not any(s["name"] == ".symtab" for s in sections)
    except (struct.error, IndexError):
        info["note"] = "section headers unreadable (possibly truncated or obfuscated)"
    if sections:
        info["sections"] = sections
    return info


PE_MACHINES = {0x14C: "x86", 0x8664: "x86-64", 0x1C0: "ARM", 0xAA64: "ARM64"}


def parse_pe(data):
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe_off, = struct.unpack_from("<I", data, 0x3C)
    if data[pe_off:pe_off + 4] != b"PE\x00\x00":
        return {"note": "MZ header without a PE signature (DOS executable?)"}
    machine, nsec, ts, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", data, pe_off + 4)
    info = {"machine": PE_MACHINES.get(machine, hex(machine)), "sections_count": nsec,
            "link_timestamp": ts, "dll": bool(chars & 0x2000)}
    opt = pe_off + 24
    magic, = struct.unpack_from("<H", data, opt)
    info["format"] = {0x10B: "PE32", 0x20B: "PE32+"}.get(magic, hex(magic))
    info["entry_rva"] = hex(struct.unpack_from("<I", data, opt + 16)[0])
    sections = []
    sec_off = opt + opt_size
    for i in range(min(nsec, 96)):
        o = sec_off + i * 40
        if o + 40 > len(data):
            break
        name = data[o:o + 8].rstrip(b"\x00").decode("latin-1")
        vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, o + 8)
        raw = data[rptr:rptr + rsize]
        sections.append({"name": name, "virtual_size": vsize, "raw_size": rsize,
                         "entropy": round(shannon(raw), 2)})
    info["sections"] = sections
    return info


def run_file_cmd(path):
    exe = shutil.which("file")
    if not exe:
        return None
    try:
        return subprocess.run([exe, "-b", path], capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        return None


def bar(e):
    return "#" * int(round(e / 8 * 24))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--blocks", type=int, default=24, help="approximate number of entropy blocks")
    ap.add_argument("--min-len", type=int, default=6, help="minimum string length")
    ap.add_argument("--strings", type=int, default=40, help="how many strings to list (0 for none)")
    ap.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024,
                    help="read at most this many bytes (default 64 MiB)")
    args = ap.parse_args()

    with open(args.file, "rb") as f:
        data = f.read(args.max_bytes)
    truncated = len(data) == args.max_bytes

    report = {
        "path": args.file,
        "size": len(data),
        "truncated_read": truncated,
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "type_by_magic": identify(data),
        "type_by_file_cmd": run_file_cmd(args.file),
        "overall_entropy": round(shannon(data), 3),
        "entropy_profile": entropy_profile(data, args.blocks),
        "embedded_signatures": embedded_signatures(data),
        "interesting": interesting(data),
    }
    strs = extract_strings(data, args.min_len)
    report["string_count"] = len(strs)
    report["strings_sample"] = [{"offset": o, "enc": e, "text": t[:120]} for o, e, t in strs[:args.strings]]
    elf, pe = parse_elf(data), parse_pe(data)
    if elf:
        report["elf"] = elf
    if pe:
        report["pe"] = pe

    if args.json:
        json.dump(report, sys.stdout, indent=2)
        print()
        return

    p = print
    p(f"File:    {report['path']}  ({report['size']} bytes{', read truncated' if truncated else ''})")
    p(f"SHA-256: {report['sha256']}")
    p(f"MD5:     {report['md5']}")
    p(f"Type:    {', '.join(report['type_by_magic']) or 'no known magic'}")
    if report["type_by_file_cmd"]:
        p(f"file(1): {report['type_by_file_cmd']}")
    p("\nFirst 64 bytes:")
    for i in range(0, min(64, len(data)), 16):
        row = data[i:i + 16]
        p(f"  {i:08x}  {row.hex(' '):<47}  {''.join(chr(b) if 32 <= b < 127 else '.' for b in row)}")
    p(f"\nEntropy (bits/byte, max 8): overall {report['overall_entropy']}")
    for blk in report["entropy_profile"]:
        flag = "  <- high (compressed/encrypted/random?)" if blk["entropy"] > 7.5 and blk["size"] >= 512 else ""
        p(f"  {blk['offset']:#010x} {blk['entropy']:5.2f} {bar(blk['entropy']):<24}{flag}")
    if report["embedded_signatures"]:
        p("\nPossible embedded data (signature hits past offset 0; short signatures can be false positives):")
        for s in report["embedded_signatures"]:
            p(f"  {s['offset']:#010x}  {s['what']}")
    if report["interesting"]:
        p("\nNotable strings:")
        for k, vals in report["interesting"].items():
            p(f"  {k}: {', '.join(vals[:8])}")
    if args.strings:
        p(f"\nStrings (min length {args.min_len}; {report['string_count']} found, showing {len(report['strings_sample'])}):")
        for s in report["strings_sample"]:
            tag = "" if s["enc"] == "ascii" else " [utf16]"
            p(f"  {s['offset']:#010x}  {s['text']}{tag}")
    if elf:
        p("\nELF header:")
        for k, v in elf.items():
            if k != "sections":
                p(f"  {k}: {v}")
        for s in elf.get("sections", [])[:40]:
            p(f"  section {s['name']:<20} addr {s['addr']:<12} off {s['offset']:#x} size {s['size']:#x}")
    if pe:
        p("\nPE header:")
        for k, v in pe.items():
            if k != "sections":
                p(f"  {k}: {v}")
        for s in pe.get("sections", []):
            p(f"  section {s['name']:<10} raw {s['raw_size']:#x} entropy {s['entropy']}")


if __name__ == "__main__":
    import signal
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)  # quiet exit when piped to head/less
    main()
