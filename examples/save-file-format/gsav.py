# Copyright (c) 2026 Likhon Sheikh <https://github.com/sheikhminds>
# SPDX-License-Identifier: MIT
"""Parser and serializer for the reconstructed GSAV save format (see spec.md)."""
import struct, zlib

MAGIC = b"GSAV"

def parse(data):
    if data[:4] != MAGIC:
        raise ValueError("bad magic")
    stored = struct.unpack_from("<I", data, len(data) - 4)[0]
    if zlib.crc32(data[:-4]) & 0xFFFFFFFF != stored:
        raise ValueError("CRC-32 mismatch")
    version, count, timestamp = struct.unpack_from("<HHI", data, 4)
    off, players = 12, []
    for _ in range(count):
        n = data[off]; off += 1
        name = data[off:off + n].decode("utf-8"); off += n
        level, hp, gold = struct.unpack_from("<BfI", data, off); off += 9
        players.append({"name": name, "level": level, "hp": hp, "gold": gold})
    if off != len(data) - 4:
        raise ValueError(f"{len(data) - 4 - off} unparsed bytes before the CRC")
    return {"version": version, "timestamp": timestamp, "players": players}

def serialize(save):
    body = MAGIC + struct.pack("<HHI", save["version"], len(save["players"]), save["timestamp"])
    for p in save["players"]:
        nb = p["name"].encode("utf-8")
        if len(nb) > 255:
            raise ValueError("name longer than 255 bytes")
        body += bytes([len(nb)]) + nb + struct.pack("<BfI", p["level"], p["hp"], p["gold"])
    return body + struct.pack("<I", zlib.crc32(body) & 0xFFFFFFFF)

if __name__ == "__main__":
    import sys, json
    for path in sys.argv[1:]:
        print(path, json.dumps(parse(open(path, "rb").read())))
