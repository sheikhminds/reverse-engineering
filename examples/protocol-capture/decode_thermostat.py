#!/usr/bin/env python3
"""Decode the reconstructed thermostat <-> hub protocol from a classic .pcap (standard library only).

Usage: decode_thermostat.py capture.pcap [--port 9100] [--readings-only]
Reassembles each TCP direction by sequence number first, so frames split across segments decode correctly.
"""
import argparse, datetime, socket, struct

MAGIC = b"\xA5\x5A"
TYPES = {0x01: "HELLO", 0x02: "HELLO_ACK", 0x10: "READING", 0x11: "ACK", 0x20: "PING", 0x21: "PONG", 0x7F: "BYE"}

def crc16_ccitt_false(data, crc=0xFFFF):
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc

def tcp_payloads(path, port):
    """Yield (direction, bytes) with each direction reassembled: 'device->hub' / 'hub->device'."""
    raw = open(path, "rb").read()
    endian = "<" if raw[:4] == b"\xd4\xc3\xb2\xa1" else ">"
    off, segs = 24, {}
    while off + 16 <= len(raw):
        _, _, caplen, _ = struct.unpack_from(endian + "IIII", raw, off); off += 16
        pkt = raw[off:off + caplen]; off += caplen
        if len(pkt) < 54 or pkt[12:14] != b"\x08\x00":      # Ethernet II + IPv4 only
            continue
        ihl = (pkt[14] & 0xF) * 4; l4 = 14 + ihl
        if pkt[23] != 6:
            continue
        sp, dp, seq, _, doff = struct.unpack("!HHIIB", pkt[l4:l4 + 13])
        data = pkt[l4 + (doff >> 4) * 4:14 + struct.unpack("!H", pkt[16:18])[0]]
        flags = pkt[l4 + 13]
        direction = "hub->device" if sp == port else "device->hub" if dp == port else None
        if direction:
            segs.setdefault(direction, []).append((seq, flags, data))
    for direction, lst in segs.items():
        syn = [s for s, f, _ in lst if f & 2]
        base = syn[0] + 1 if syn else min(s for s, _, d in lst if d)
        stream = bytearray()
        for seq, _, data in sorted(lst, key=lambda t: (t[0] - base) & 0xFFFFFFFF):
            pos = (seq - base) & 0xFFFFFFFF
            if data and pos + len(data) > len(stream):
                stream[pos:] = data[len(stream) - pos:] if pos < len(stream) else data
        yield direction, bytes(stream)

def frames(stream):
    off = 0
    while off + 9 <= len(stream):
        if stream[off:off + 2] != MAGIC:
            raise ValueError(f"lost frame sync at byte {off}")
        mtype, seq, ln = struct.unpack_from(">BHH", stream, off + 2)
        end = off + 7 + ln + 2
        if end > len(stream):
            raise ValueError("truncated frame at end of stream")
        body = stream[off + 2:end - 2]
        crc_ok = crc16_ccitt_false(body) == struct.unpack(">H", stream[end - 2:end])[0]
        yield mtype, seq, stream[off + 7:end - 2], crc_ok
        off = end

def describe(mtype, payload):
    if mtype == 0x01:
        return f"device_id={payload.decode('ascii')}"
    if mtype == 0x02:
        session, interval = struct.unpack(">IH", payload)
        return f"session={session:#010x} interval={interval}s"
    if mtype == 0x10:
        sensor, t10, hum, ts = struct.unpack(">BhBI", payload)
        when = datetime.datetime.fromtimestamp(ts, datetime.UTC).strftime("%Y-%m-%d %H:%M:%S")
        return f"sensor={sensor} temp={t10 / 10:.1f} C humidity={hum}% time={when}Z"
    if mtype == 0x11:
        return f"acked_seq={struct.unpack('>H', payload)[0]}"
    return ""

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap"); ap.add_argument("--port", type=int, default=9100)
    ap.add_argument("--readings-only", action="store_true")
    a = ap.parse_args()
    bad = 0
    for direction, stream in tcp_payloads(a.pcap, a.port):
        for mtype, seq, payload, crc_ok in frames(stream):
            bad += not crc_ok
            if a.readings_only and mtype != 0x10:
                continue
            name = TYPES.get(mtype, f"UNKNOWN_{mtype:#04x}")
            print(f"{direction:12s} seq={seq:<3d} {name:<10s} {describe(mtype, payload)}{'' if crc_ok else '   ** CHECKSUM FAILED **'}")
    print(f"\n{'all checksums valid' if not bad else f'{bad} frame(s) failed the checksum'}")
