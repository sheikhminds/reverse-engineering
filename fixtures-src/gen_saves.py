import struct, zlib, os
def save(players, ts, version=3):
    body = b"GSAV" + struct.pack("<HHI", version, len(players), ts)
    for name, level, hp, gold in players:
        nb = name.encode("utf-8")
        body += struct.pack("<B", len(nb)) + nb + struct.pack("<BfI", level, hp, gold)
    return body + struct.pack("<I", zlib.crc32(body) & 0xffffffff)
out = "save-files"
os.makedirs(out, exist_ok=True)
open(f"{out}/empty.sav","wb").write(save([], 1762600000))
open(f"{out}/one-player.sav","wb").write(save([("Ann",5,87.5,1200)], 1762603600))
open(f"{out}/one-player-later.sav","wb").write(save([("Ann",6,100.0,1350)], 1762607200))
open(f"{out}/two-players.sav","wb").write(save([("Ann",6,100.0,1350),("Boris",2,42.25,75)], 1762610800))
