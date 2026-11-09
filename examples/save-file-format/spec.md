# GSAV save file format (reconstructed)

Samples examined: 4 (`empty`, `one-player`, `one-player-later`, `two-players`). Byte order: little-endian throughout. Status: parses and byte-for-byte round-trips all four samples; see "Unknowns".

## Layout

| Offset | Size | Type | Name | Meaning | Confidence | Evidence |
|---|---|---|---|---|---|---|
| 0 | 4 | bytes | magic | ASCII `GSAV` | Confirmed | Identical in all 4 files |
| 4 | 2 | u16 | version | `3` in every sample | Confirmed (value), Guess (meaning) | Constant `03 00` in all files |
| 6 | 2 | u16 | player_count | Number of player records | Confirmed | 0, 1, 1, 2 in the four files; file length grows by one record per player |
| 8 | 4 | u32 | timestamp | Unix time in seconds | Likely | Values fall in Nov 2025; one-player-later differs from one-player by exactly +3600 |
| 12 | var | record[player_count] | players | See below | Confirmed | Sizes: 29-16 = 13 = 1+3+9 (name "Ann"); 44-29 = 15 = 1+5+9 (name "Boris") |
| end-4 | 4 | u32 | crc32 | CRC-32 (zlib/IEEE) of all preceding bytes | Confirmed | Computed value equals stored value in all 4 files |

### Player record

| Offset | Size | Type | Name | Meaning | Confidence | Evidence |
|---|---|---|---|---|---|---|
| 0 | 1 | u8 | name_len | Length of name in bytes | Confirmed | `03`, then "Ann"; `05`, then "Boris" |
| 1 | n | UTF-8 | name | Character name, no terminator | Confirmed (ASCII), Likely (UTF-8) | Only ASCII names seen |
| 1+n | 1 | u8 | level | Character level | Confirmed | 5 -> 6 for Ann between saves; 2 for Boris |
| 2+n | 4 | float32 | hp | Hit points | Confirmed | 87.5, 100.0, 42.25 decode exactly |
| 6+n | 4 | u32 | gold | Gold | Confirmed (value), Likely (width) | 1200, 1350, 75 decode exactly; top two bytes were always zero, so u16 plus padding can't be excluded |

## Worked example: `two-players.sav` (44 bytes)

```
47 53 41 56            magic "GSAV"
03 00                  version 3
02 00                  2 players
70 4e 0f 69            timestamp 0x690f4e70 = 1762610800
03 41 6e 6e            name_len 3, "Ann"
06 | 00 00 c8 42 | 46 05 00 00     level 6, hp 100.0, gold 1350
05 42 6f 72 69 73      name_len 5, "Boris"
02 | 00 00 29 42 | 4b 00 00 00     level 2, hp 42.25, gold 75
80 38 5c 35            CRC-32 0x355c3880
```

## Unknowns (and what would resolve them)

- **Version meaning.** Only version 3 was seen. A save from another game version would show whether the layout changes.
- **Timestamp meaning.** It could be the save time or total play time in some epoch. A save made at a known moment would settle it.
- **Gold and level widths.** Need a save with gold above 65,535 (and a level above 255, if possible).
- **Non-ASCII names.** Need a character name with accents or non-Latin letters.
- **Limits.** Maximum players and the maximum name length the game itself accepts are unknown (the format allows 65,535 and 255).

## How this was established

1. The empty save (16 bytes) shows the fixed overhead: 12-byte header plus 4-byte trailer.
2. `hexdiff.py` between `one-player` and `one-player-later` isolated the timestamp (+3600), level (+1), HP and gold fields, and the trailing 4 bytes, which changed whenever anything else did.
3. The trailer was tested as CRC-32 over `data[:-4]` and matched in all samples.
4. `gsav.py` parses all samples to the values you gave me and `serialize(parse(x)) == x` for each.
