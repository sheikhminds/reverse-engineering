# Copyright (c) 2026 Likhon Sheikh <https://github.com/sheikhminds>
# SPDX-License-Identifier: MIT
import struct, socket
def crc16(data, poly=0x1021, init=0xFFFF):
    crc = init
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc
def msg(mtype, seq, payload=b""):
    core = struct.pack(">BHH", mtype, seq, len(payload)) + payload
    return b"\xA5\x5A" + core + struct.pack(">H", crc16(core))
DEV, HUB = ("192.168.1.50", 49152), ("192.168.1.10", 9100)
pkts, t = [], 1762700000.0
state = {DEV: 1000, HUB: 5000}
def tcp(src, dst, flags, payload=b"", ack=0):
    global t
    t += 0.1
    seq = state[src]
    th = struct.pack("!HHIIBBHHH", src[1], dst[1], seq, ack, 5 << 4, flags, 65535, 0, 0)
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + 20 + len(payload), 0, 0, 64, 6, 0,
                      socket.inet_aton(src[0]), socket.inet_aton(dst[0]))
    eth = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00"
    pkts.append((t, eth + iph + th + payload))
    state[src] += len(payload) + (1 if flags & 0x03 else 0)
def send(src, dst, data, split=None):
    parts = [data] if split is None else [data[:split], data[split:]]
    for p in parts:
        tcp(src, dst, 0x18, p, ack=state[dst])
    tcp(dst, src, 0x10, b"", ack=state[src])       # bare TCP ACK
tcp(DEV, HUB, 0x02); tcp(HUB, DEV, 0x12, ack=state[DEV]); tcp(DEV, HUB, 0x10, ack=state[HUB])
send(DEV, HUB, msg(0x01, 1, b"THERM-7F3A"))
send(HUB, DEV, msg(0x02, 1, struct.pack(">IH", 0x00C0FFEE, 30)))
base = 1762700030
send(DEV, HUB, msg(0x10, 2, struct.pack(">BhBI", 1, 215, 45, base)));       send(HUB, DEV, msg(0x11, 2, struct.pack(">H", 2)))
send(DEV, HUB, msg(0x10, 3, struct.pack(">BhBI", 1, 217, 46, base + 30)), split=7); send(HUB, DEV, msg(0x11, 3, struct.pack(">H", 3)))
send(DEV, HUB, msg(0x10, 4, struct.pack(">BhBI", 2, -35, 80, base + 60)));  send(HUB, DEV, msg(0x11, 4, struct.pack(">H", 4)))
send(DEV, HUB, msg(0x20, 5));  send(HUB, DEV, msg(0x21, 5))
send(DEV, HUB, msg(0x7F, 6))
hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
with open("thermostat.pcap", "wb") as f:
    f.write(hdr)
    for ts, p in pkts:
        f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(p), len(p)) + p)
print(len(pkts), "packets")
