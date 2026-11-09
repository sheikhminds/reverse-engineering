---
name: reverse-engineering
description: Systematic reverse engineering of things that have no source code or documentation - compiled binaries and firmware (disassembly, decompilation, static and dynamic analysis), unknown or undocumented file formats and data structures, network protocols and undocumented APIs (from packet captures, HAR files, traffic logs), and legacy code or systems nobody understands anymore. Use this skill whenever the user wants to work out how something functions from the outside - "what does this binary do", "what's the format of this file", "decode this protocol", "make sense of this hex dump", "document this legacy system", "write a parser for this unknown format", "rebuild the spec" - even if they never say "reverse engineering". Covers interoperability, security research on software the user is authorized to analyze, CTFs and learning, data recovery, and legacy migration. Not for cracking licences or DRM, developing exploits, or analyzing or building malware.
---

# Reverse Engineering

Reverse engineering is the scientific method applied to a black box: you have the finished thing, not the blueprints, so you observe it, form hypotheses about how it was built, test them, and write down what survives. This skill gives you a repeatable way to do that for four kinds of target, plus helper scripts for the mechanical parts.

## Scope and ground rules

Legitimate uses this skill is built for: interoperability and compatibility, understanding or documenting software the user owns or is authorized to analyze, defensive security research, CTFs and education, recovering data from abandoned formats, and migrating legacy systems.

Decline these parts, briefly and without a lecture, and offer the legitimate neighbour of the request if there is one:

- Defeating licensing, DRM, copy protection, or anti-cheat.
- Developing exploits, or probing live systems the user doesn't own. Work from captured traffic and local copies instead.
- Analyzing, modifying, or improving malware. If a sample looks malicious, say it's outside what this skill covers and stop at identifying the file type.
- Decrypting traffic or data the user isn't authorized to access.

Treat every unknown executable as untrusted. Analyze statically first. Run something only when there's a concrete reason, with a timeout, no network, and in a throwaway directory. Tell the user when you do.

## The core loop

1. **Observe.** Collect facts without interpreting them: bytes, strings, headers, calls, messages, outputs.
2. **Hypothesize.** State a specific, falsifiable guess ("bytes 4-7 are a little-endian length of the payload").
3. **Test.** Design the cheapest experiment that could prove it wrong: another sample, a one-byte change, a different input, a computed check.
4. **Record.** Write down what's confirmed, what's likely, and what's a guess. Revisit when new evidence arrives.

Four habits that make this work, and why:

- **Triage before depth.** Knowing it's a UPX-packed ELF, a zlib stream, or a length-prefixed TCP protocol changes every later step, and it takes seconds to find out.
- **Outside in.** Start from interfaces (command line, imports and exports, file headers, message envelopes) and work toward internals. Interfaces are small and carry most of the meaning.
- **Change one thing at a time.** Differential analysis (vary one input, diff the output) is the most reliable tool you have, because it isolates cause from effect without needing to understand anything else.
- **Prove it by round trip.** A parser that reads every sample and a serializer that reproduces the original bytes is evidence. A prose description of the format is a guess until then.

Label every claim with a confidence level and the evidence behind it: **Confirmed** (observed and reproduced), **Likely** (fits all the evidence, not yet tested against a counterexample), or **Guess**. Readers will act on your findings, so they need to know which ones to lean on.

## Workflow

### 1. Clarify the goal

What will the user do with this understanding? "Rewrite it", "interoperate with it", "audit it", "just understand it" need different depths. Infer from the request when you can. Ask one question only if the answer would change the approach.

### 2. Inventory your tools

Check before assuming. Environments differ.

```bash
for t in file strings xxd objdump readelf nm gcc python3 ghidra analyzeHeadless r2 rizin gdb strace ltrace tshark binwalk; do
  printf "%-16s" $t; command -v $t || echo "-"
done
python3 -c "import capstone" 2>&1 | tail -1
```

In a typical Claude.ai sandbox you'll have `file`, `strings`, `xxd`, `objdump`, `readelf`, `nm`, `gcc` and Python, and can `pip install --break-system-packages capstone pefile lief pyelftools scapy construct`. On a user's own machine (Claude Code, Cowork) there may be Ghidra, radare2, Wireshark and a debugger. Use what exists; the method doesn't depend on any one tool.

### 3. Triage

```bash
python3 scripts/triage.py <file>            # type, hashes, entropy profile, embedded signatures, strings, ELF/PE header
python3 scripts/triage.py <file> --json     # same, machine-readable
```

Read the entropy profile with care. High entropy means compressed *or* encrypted *or* random, and it is not proof of encryption. Low and patterned means tables, text, or code.

### 4. Route to the domain reference

Read the reference that matches the target. Many real tasks cross domains (a binary that parses a file format and talks a protocol), so read more than one when needed.

| The target is... | Read |
|---|---|
| Executable, shared library, firmware image, object file, bytecode (`.class`, `.pyc`, `.dex`, `.wasm`, .NET) | `references/binaries.md` |
| An unknown data file: save game, database, archive, config blob, proprietary export | `references/file-formats.md` |
| A packet capture, hex dump of messages, HAR file, API traffic log, serial or USB trace, undocumented API | `references/network-protocols.md` |
| A codebase, system, or process with missing docs: old source, stored procedures, COBOL, macros, batch jobs | `references/legacy-code.md` |

### 5. Analyze, keeping a findings log

Keep a running `findings.md` as you go (offsets, names you assigned, hypotheses and their status). Rediscovering your own conclusions twenty steps later is the most common way to waste time. When you name something you can't be sure of (a function in a stripped binary, an unknown field), name it for what it does or where it is (`fn_0x401230_checks_header`, `field_at_0x08`) rather than for what you hope it is.

### 6. Deliver

Match the deliverable to the goal. Always include how a reader can verify your claims.

**Analysis report** (binaries, legacy systems):

```markdown
# <Target>: analysis
## Summary
3-5 sentences: what it is, what it does, how sure you are.
## Findings
| Finding | Evidence | Confidence |
## Interfaces
Command line, inputs, outputs, files touched, network endpoints.
## Open questions
## How to verify
Commands or scripts that reproduce the key findings.
```

**Format or protocol spec** (file formats, network protocols):

```markdown
# <Name> format specification (reconstructed)
Samples examined: N. Byte order: ... Status: ...
| Offset | Size | Type | Name | Meaning | Confidence | Evidence |
## Worked example
One real sample, annotated byte by byte.
## Unknowns
Fields whose meaning isn't established, and what would resolve them.
```

**Working artifacts** are often the best deliverable: a parser or decoder script that round-trips every sample, struct definitions (Python `struct`, `construct`, a C header, or a Kaitai `.ksy`), an OpenAPI file, a replay client, characterization tests. Test them against all samples before you hand them over and say what you tested.

## Helper scripts

All scripts are standard-library Python, so they run anywhere. Run each with `--help`.

| Script | Use it to |
|---|---|
| `scripts/triage.py` | Identify a file, hash it, profile entropy, find embedded signatures and strings, read ELF/PE headers |
| `scripts/hexdiff.py` | Compare two files and list the changed regions. The workhorse of differential analysis |
| `scripts/probe.py` | Show how the bytes at an offset read as every plausible type (ints, floats, timestamps, strings) |
| `scripts/pcap_flows.py` | Summarize a classic `.pcap`: TCP/UDP flows, then dump one flow's payloads by direction |

## Pitfalls worth remembering

- **Anchoring.** The first hypothesis feels right because it's the only one you have. Keep a second candidate alive until evidence separates them.
- **Encoding is not encryption.** Base64, zlib, XOR with a constant, and varints all look opaque and aren't. Try the cheap decodings before concluding anything is encrypted, and say plainly when you hit data you can't read without a key.
- **One sample proves little.** Constants look like fields and fields look like constants. Get at least three varied samples, including the smallest and a deliberately empty one.
- **Byte-level traps.** Endianness, alignment padding, signed versus unsigned, and 32 versus 64-bit sizes account for a large share of "this doesn't parse" moments.
- **Decompiler output is a draft.** Types, loop shapes, and names are inferred and sometimes wrong. Confirm anything important against the disassembly.
- **Don't overclaim.** "The binary calls `connect` with a hard-coded address" is an observation. "The binary phones home" is an interpretation. Report the observation, then label the interpretation.

<!-- Copyright (c) 2026 Likhon Sheikh - https://github.com/sheikhminds - MIT License -->
