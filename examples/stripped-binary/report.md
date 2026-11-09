# `rle`: analysis

## Summary
`rle` is a small command-line run-length encoder and decoder for text. `rle aaabcc` prints `3a1b2c`, and `rle -d 3a1b2c` turns it back into `aaabcc`. It is a stripped 64-bit x86-64 Linux PIE (ELF), dynamically linked against glibc. It reads its text from the command line only, touches no files, and uses no network. Its own banner calls it `rle-lite 1.3.2`. Confidence is high: every behaviour below was seen both in the binary and in sandboxed runs.

## Interfaces

Usage string in the binary: `usage: rle [-d] [-s] [-V] TEXT`

| Option | Effect | Evidence |
|---|---|---|
| (none) `TEXT` | Encode TEXT | `rle aaabcc` -> `3a1b2c` |
| `-d` | Decode TEXT instead of encoding | `rle -d 3a1b2c` -> `aaabcc` |
| `-s` | Also print `in=<n> out=<n>` (input and output lengths) on **stderr** | `rle -s aaabcc` -> stderr `in=6 out=6` |
| `-V` | Print `rle-lite 1.3.2` to stdout, exit 0 | run, and the string is in `.rodata` |
| `-h` | Print usage to **stdout**, exit 0 | run |

The last argument that is not an option is taken as TEXT. Options are matched by exact `strcmp` against `-d`, `-s`, `-V`, `-h` (`.rodata` offsets 0x2004-0x200f), so they can't be combined (`-ds` would be treated as text).

## Encoding rules
- Output is a sequence of `<count><char>` pairs, with the count in decimal. `abc` -> `1a1b1c`.
- A run is **capped at 99**. 120 `a`s encode to `99a21a`, 100 `x`s to `99x1x`, 198 to `99x99x`. In the disassembly this is `lea r12,[rcx+0x63]` at 0x144f (run end limit = start + 99), followed by `cmp rax,r12` in the inner loop.
- Any other byte (spaces, punctuation) is a normal character: `ab ba` -> `1a1b1 1b1a`.
- The output buffer is allocated as `strlen(text) * 100 + 2` bytes (`imul r14, rax, 0x64` at 0x1330), which is enough for the worst case.

## Decoding rules
- Reads `<count><char>` pairs. Counts can have several digits (`12x` -> twelve `x`).
- Rejects: a character where a count should be (`a`), a count with no character after it (`3`, `3a1`), and a count of zero (`0a`).

## Exit codes and messages

| Code | Condition | Message (stderr) |
|---|---|---|
| 0 | Success (including `-h`, `-V`, empty text) | none |
| 2 | No TEXT given | `usage: rle [-d] [-s] [-V] TEXT` |
| 3 | Malformed input while decoding | `error: malformed input` |
| 4 | Digits in the text to encode | `error: digits not allowed in input` |

Rule 4 exists because digits in the input would make the output ambiguous (`11` could not be told apart from a count). Treat that as my interpretation. The binary only shows that digits are rejected.

## Observation versus interpretation
- **Observed:** the strings, imports (`strlen`, `strcmp`, `malloc`, `__sprintf_chk`, `__fprintf_chk`, `puts`, `fwrite`, `__ctype_b_loc`; no sockets, no `exec*`, no file I/O), the disassembly of `main` (found via the entry point: the address loaded into `rdi` before the call to `__libc_start_main` is `main` at 0x1229), and the outputs of about 20 runs.
- **Interpreted:** the reason digits are rejected; that `-s` stands for "stats".
- **Not examined:** behaviour for non-ASCII bytes beyond treating them as plain bytes (`isdigit` is locale-dependent in principle), and extremely large inputs.

## How the runs were done
Because the import list showed no network, process, or file functions, I ran the binary a few times in a scratch directory with `timeout 5` and an empty environment, varying one argument at a time. I ran nothing else.

## If you need to rebuild it
A C reimplementation needs: the argument loop above, an encoder that scans runs up to 99 and prints `%zu%c`, a decoder that accumulates digits and then repeats the next byte, and the four exit paths. The banner and usage strings are given verbatim above. Test it against the 20-odd input/output pairs in this report; they're a ready-made characterization suite.
