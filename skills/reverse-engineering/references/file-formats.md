# Reverse engineering file formats and data structures

Contents: 1. Gather samples - 2. First look - 3. Find the structure - 4. Identify field types - 5. Differential analysis - 6. Checksums and compression - 7. Write the spec and a parser - 8. Validate

Read `SKILL.md` first for scope and the core loop. This reference assumes the user owns the files or is authorized to work with them, for example to migrate, recover, or interoperate.

## 1. Gather samples

The quality of the result tracks the quality of the sample set. Ask the user for, or generate:

- At least three or four files, and more is better.
- The **smallest** possible file (empty document, new game, zero records). It shows the fixed header and the fixed overhead.
- **Pairs that differ by one known thing**, if the user can run the originating application: change one setting, add one record, rename one item, save again. These are worth more than a dozen unrelated files.
- Files from different versions of the application, if they exist. Version differences expose which fields are optional or newer.

Note what each sample contains in the real world ("3 players, score 1200, name 'Ann'"). Ground truth you can compare against turns guessing into testing.

## 2. First look

```bash
python3 scripts/triage.py sample.bin
xxd sample.bin | head -40
```

Check, in order:

1. **Magic bytes** at offset 0 (and at the end, for trailers such as ZIP's end-of-central-directory or PNG's `IEND`). Also check whether it's a known container in disguise: ZIP (`PK\x03\x04`), gzip (`1f 8b`), zlib (`78 9c`/`78 da`/`78 01`), SQLite (`SQLite format 3`), PNG, RIFF, tar (`ustar` at offset 257). Many "proprietary" formats are a zip or SQLite with a renamed extension.
2. **Text.** Is it JSON, XML, INI, base64, or hex in disguise? Plain `strings` often settles it.
3. **Entropy profile.** Near 8.0 bits/byte throughout means compressed, encrypted, or random. A low-entropy header followed by a high-entropy body is the classic "header plus compressed payload".
4. **Size relationships.** Does file size minus a constant equal a number found near the start? That's a length field. Do sizes of different samples differ by a regular step? That's a fixed record size.

## 3. Find the structure

**Header.** Look for: magic, version, flags, total length or payload length, counts, offsets to other sections, and reserved or zero padding. A header field equal to a nearby offset or the file size is easy to spot and very informative.

**Records.** Repetition is the signature of a table. Look for a stride: the same bytes recurring every N bytes (small integers that count up, constant flag bytes). Sizes in the sample set that differ by exactly N per added record confirm N.

**Strings.** Identify how they're stored, because it fixes how you parse everything around them:

- Null-terminated (`"Ann\0"`).
- Length-prefixed ("Pascal"): a 1, 2, or 4-byte length before the characters. Check by seeing whether the byte before a string equals its length.
- Fixed-width, padded with zeros or spaces.
- UTF-16LE (every other byte is `00` for ASCII text) or UTF-8.

**Variable-length integers.** Bytes where the high bit signals "more follows" suggest varints (LEB128, protobuf). If most bytes look like `0x08`, `0x12`, `0x1a` followed by lengths, try the protobuf wire format: tag = `(field_number << 3) | wire_type`, wire types 0 (varint), 1 (64-bit), 2 (length-delimited), 5 (32-bit).

**Offset tables.** A run of increasing integers that all point inside the file usually indexes later sections. Jump to each target and see what's there.

**Tagged or TLV layouts.** A stream of (type, length, value) triples. The test is that skipping `length` bytes from each header lands exactly on the next header and ends exactly at the end of the file.

## 4. Identify field types

Use `scripts/probe.py sample.bin OFFSET` to see how the bytes at a position read as every plausible type at once. Then judge by plausibility:

| Reads as | Plausible when |
|---|---|
| uint8/16/32, little or big endian | Small counts, IDs, flags. A value that is small in one byte order and huge in the other tells you the endianness |
| int (signed) | Offsets, deltas, coordinates, temperatures |
| float32/float64 | Values in a sensible range (a health of `100.0`, a latitude within +/-90). Garbage floats are typically absurdly large or tiny, or NaN |
| Unix timestamp (seconds) | Roughly 1.2e9-1.9e9 for 2008-2030. Milliseconds is the same scaled by 1000 |
| Windows FILETIME | About 1.3e17 for recent dates (100 ns ticks since 1601) |
| Bit flags | Few bits set, values like `0x01`, `0x03`, `0x80` |
| ASCII / UTF-16 | Runs of printable bytes |

Remember **endianness** (try both), **alignment padding** (zero bytes between fields often exist so that the next field starts on a multiple of 2, 4, or 8), and **signedness**.

## 5. Differential analysis

When you have two samples that differ by one known change:

```bash
python3 scripts/hexdiff.py before.bin after.bin
```

- A change confined to a few bytes at a fixed offset locates that field. Compare what changed in the file with what changed in the world.
- Change a value through several steps (1, 2, 3, 10, 255, 256, 1000) and watch the bytes. This reveals the integer width, endianness, and any encoding (varint, BCD, fixed-point, scaled by 10 or 100).
- A change that ripples through a lot of the file points to **compression, encryption, or a checksum/offset table that shifted**. Separate these by checking whether bytes *after* the changed region are merely shifted (offsets or inserted data) or completely different (compression or encryption).
- Bytes that change on every save even with identical content are usually timestamps, counters, or random IDs or salts.

## 6. Checksums, compression, and obfuscation

**Checksums.** A few trailing or header bytes that change whenever anything else does. Test candidates over plausible ranges (the whole file minus the checksum field, or the payload only):

```python
import zlib, binascii
data = open("sample.bin","rb").read()
stored = int.from_bytes(data[-4:], "little")            # or "big", or a header field
for name, fn in [("crc32", zlib.crc32), ("adler32", zlib.adler32)]:
    for lo in range(0, 32):
        if fn(data[lo:-4]) & 0xffffffff == stored:
            print("match", name, "range", lo, "to -4")
```

Also try sum-of-bytes (mod 256 or 65536), XOR of bytes, and CRC-16 variants. Zero the checksum field itself before computing when it lies inside the covered range.

**Compression.** Try decompressing the high-entropy region from the offset right after the header:

```python
import zlib, bz2, lzma, gzip
blob = data[HEADER_LEN:]
for name, f in [("zlib", zlib.decompress),
                ("raw-deflate", lambda b: zlib.decompress(b, -15)),
                ("gzip", gzip.decompress), ("bz2", bz2.decompress), ("lzma", lzma.decompress)]:
    try:
        out = f(blob); print(name, "ok", len(out)); break
    except Exception as e:
        pass
```

Common formats to try also include LZ4, Zstandard, and LZSS variants, though those need extra libraries or hand-written decoders.

**Obfuscation.** Single-byte XOR (look for a repeated byte in what should be zero padding; a block of `0x5A` where you'd expect `0x00` implies key `0x5A`), simple rotation, or a repeating-key XOR. Easy to check, easy to rule out.

**Real encryption.** If the payload is high-entropy, no decompressor works, and no key or algorithm is in sight, say so. Without the key, this is a stopping point. If an application is meant to open the file, the key or algorithm lives in that application, which is a binary-analysis question (see `binaries.md`), and only worth pursuing for software the user is authorized to analyze.

## 7. Write the spec and a parser

Produce both: the table in the `SKILL.md` template and code that implements it. Code forces precision, and a spec that nobody has run is only a guess.

A minimal pattern using `struct`:

```python
import struct

def parse(data):
    magic, version, count = struct.unpack_from("<4sHH", data, 0)
    assert magic == b"ABCD", "bad magic"
    off, records = 8, []
    for _ in range(count):
        rid, value = struct.unpack_from("<Hf", data, off); off += 6
        n = data[off]; off += 1
        name = data[off:off+n].decode("utf-8"); off += n
        records.append((rid, value, name))
    return records
```

Write a matching serializer too. If `serialize(parse(x)) == x` for every sample, you've shown that you understand every byte, including padding. If you can't produce identical bytes, find out why: an unparsed field, a timestamp, uninitialized padding, or a checksum.

For larger formats consider `construct` (`pip install --break-system-packages construct`) or a Kaitai Struct `.ksy` description, which is declarative and can generate parsers in many languages:

```yaml
meta: {id: save_file, endian: le}
seq:
  - {id: magic, contents: "SAVG"}
  - {id: version, type: u2}
  - {id: num_records, type: u2}
  - {id: records, type: record, repeat: expr, repeat-expr: num_records}
types:
  record:
    seq:
      - {id: rec_id, type: u2}
      - {id: value, type: f4}
      - {id: name_len, type: u1}
      - {id: name, type: str, size: name_len, encoding: UTF-8}
```

## 8. Validate

Before calling the spec done:

- Parse **every** sample without errors and with sensible values.
- Check the round trip described above.
- Try a sample from a different version, or one with unusual content (empty strings, maximum-length names, zero records, large numbers). Boundary cases are where field widths and encodings reveal their errors.
- List what remains **Unknown** (reserved fields, flags whose meaning you never saw change) rather than guessing. Say what experiment would resolve each.

<!-- Copyright (c) 2026 Likhon Sheikh - https://github.com/sheikhminds - MIT License -->
