<div align="center">

<img src="https://cdn-icons-png.flaticon.com/512/5231/5231459.png" width="96" height="96" alt="Reverse Engineering icon">

# Reverse Engineering

**A Claude skill that teaches an assistant to work out how closed systems behave, and to write down only what survived testing.**

[![smoke test](https://github.com/sheikhminds/reverse-engineering/actions/workflows/test.yml/badge.svg)](https://github.com/sheikhminds/reverse-engineering/actions/workflows/test.yml)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB.svg?logo=python&logoColor=white)](#requirements)

[Overview](#overview) | [Install](#install) | [Quick start](#quick-start) | [What's inside](#whats-inside) | [Method](#method) | [Scripts](#helper-scripts) | [Testing](#testing) | [Contributing](#contributing)

</div>

## Overview

This repository packages a [Claude skill](https://docs.claude.com) for reverse engineering things that have no source code or documentation: compiled binaries, unknown file formats, network protocols, and legacy systems.

The method is the same for every target: **observe, hypothesize, test, record**. Every claim carries a confidence label so readers know what to rely on:

| Label | Meaning |
|---|---|
| **Confirmed** | Observed and reproduced, with the evidence cited |
| **Likely** | Fits all the evidence, not yet tested against a counterexample |
| **Guess** | A working hypothesis that still needs a test |

The skill is built for interoperability, documentation of software you own or are authorized to analyze, defensive security research, CTFs and education, data recovery, and legacy migration. It is not for cracking licenses or DRM, developing exploits, or analyzing or building malware.

## What it covers

| Target | What the skill does |
|---|---|
| **Compiled binaries, firmware, bytecode** | Triage, static analysis, reading disassembly, sandboxed differential runs, and verifying a reimplementation |
| **Unknown file formats** | Gather samples, find headers, records and checksums, run change-one-thing diffs, write a spec **and** a parser that round-trips |
| **Network protocols and undocumented APIs** | Reassemble streams, find framing and envelope, cluster message types, identify checksums, and produce a catalog, state machine, and decoder |
| **Legacy code and systems** | Inventory, characterization tests, business-rule extraction, data dictionary, and a risk register |

## Install

### Claude Code / Cowork

```bash
git clone https://github.com/sheikhminds/reverse-engineering.git
cp -r reverse-engineering/skills/reverse-engineering ~/.claude/skills/      # personal
# or: cp -r ... your-project/.claude/skills/                                # one project
```

### Claude.ai

The `.skill` file is a zip archive. Build one from the `skills/` directory, then upload it wherever Claude.ai lets you add skills:

```bash
cd reverse-engineering/skills
zip -r reverse-engineering.skill reverse-engineering -x "reverse-engineering/evals/*"
```

On Windows PowerShell, replace the `zip` line with `Compress-Archive -Path reverse-engineering -DestinationPath reverse-engineering.zip` and upload the resulting archive (rename it to `.skill` if your client requires that extension).

Then ask for something concrete - *"what's the format of this file?"*, *"decode this packet capture"*, *"what does this stripped binary do?"* - and attach the material. The skill triggers on the task, not on the words "reverse engineering".

## Quick start

The helper scripts run on their own with the Python standard library (no installs):

```bash
# Identify an unknown file: type, hashes, entropy, embedded signatures, strings, ELF/PE headers
python skills/reverse-engineering/scripts/triage.py some.bin

# See exactly which bytes changed between two saves
python skills/reverse-engineering/scripts/hexdiff.py before.sav after.sav

# Read the bytes at an offset as every plausible type
python skills/reverse-engineering/scripts/probe.py file.bin 0x10

# List flows in a classic .pcap and reassemble one
python skills/reverse-engineering/scripts/pcap_flows.py capture.pcap --flow 0
```

Every script supports `--help`; `triage.py` also supports `--json` for machine-readable output.

## What's inside

```text
skills/reverse-engineering/
├── SKILL.md                 method, scope, workflow, report and spec templates
├── references/
│   ├── binaries.md          binaries, firmware, bytecode
│   ├── file-formats.md      unknown file formats
│   ├── network-protocols.md captures, HAR files, undocumented APIs
│   └── legacy-code.md       systems with no documentation
├── scripts/                 standard-library Python, no installs needed
│   ├── triage.py            type, hashes, entropy profile, signatures, strings, ELF/PE headers
│   ├── hexdiff.py           changed regions between two files (differential analysis)
│   ├── probe.py             read bytes as integers, floats, timestamps, strings, varints
│   └── pcap_flows.py        flows and reassembled payloads from a classic .pcap
└── evals/                   three test cases in the layout `claude plugin eval` reads
examples/                    worked results for the three eval cases
fixtures-src/                generators and C source for the files used by the evals
tests/smoke_test.py          end-to-end checks for the scripts and examples
AGENTS.md                    conventions for AI agents working in this repository
```

## Method

The skill drives a four-step loop:

1. **Observe.** Collect facts without interpreting them: bytes, strings, headers, calls, messages, outputs.
2. **Hypothesize.** State a specific, falsifiable guess, for example "bytes 4-7 are a little-endian payload length".
3. **Test.** Design the cheapest experiment that could prove it wrong: another sample, a one-byte change, a different input, a computed check.
4. **Record.** Write down what is confirmed, likely, and still a guess, and revisit when new evidence arrives.

Four habits make it work: **triage before depth**, work **outside in**, **change one thing at a time**, and **prove it by round trip**. The full workflow, scope rules, and deliverable templates live in [`SKILL.md`](skills/reverse-engineering/SKILL.md).

## Helper scripts

| Script | Use it to |
|---|---|
| [`triage.py`](skills/reverse-engineering/scripts/triage.py) | Identify a file, hash it, profile entropy, find embedded signatures and strings, read ELF/PE headers |
| [`hexdiff.py`](skills/reverse-engineering/scripts/hexdiff.py) | Compare two files and list changed regions - the workhorse of differential analysis |
| [`probe.py`](skills/reverse-engineering/scripts/probe.py) | Show how the bytes at an offset read as every plausible type |
| [`pcap_flows.py`](skills/reverse-engineering/scripts/pcap_flows.py) | Summarize a classic `.pcap` and dump one flow's payloads by direction |

All four are POSIX-friendly and work on Windows, macOS, and Linux. `triage.py` caps its read at 64 MiB by default, and none of the scripts modify their inputs.

## Evals and examples

Three cases with known answers were run end to end and are reproduced under [`examples/`](examples/):

| Case | Target | Expected outcome |
|---|---|---|
| [`infer-save-file-format`](skills/reverse-engineering/evals/infer-save-file-format/) | Custom save-file format | Header, player records, and CRC-32 trailer reconstructed; parser round-trips all samples |
| [`document-stripped-linux-tool`](skills/reverse-engineering/evals/document-stripped-linux-tool/) | Stripped x86-64 Linux binary | Options, exit codes, and hidden run-length cap of 99 documented from evidence |
| [`reconstruct-thermostat-protocol`](skills/reverse-engineering/evals/reconstruct-thermostat-protocol/) | Toy TCP sensor protocol in a `.pcap` | Envelope, message types, and CRC-16/CCITT-FALSE recovered; decoder handles a split TCP message |

These are sanity checks, not blind benchmarks: the skill and inputs were written together and graded by the same author. Real-world artifacts will be harder.

## Requirements

- **Python 3.11 or newer** for the helper scripts and tests.
- **No third-party packages** - everything uses the standard library.
- Optional external tools (`file`, `strings`, `objdump`, `readelf`, `gcc`, `tshark`) improve results when present but are never required.
- The eval binary (`evals/document-stripped-linux-tool/files/rle`) is prebuilt for x86-64 Linux; rebuild it with `gcc -O1 -s -o rle fixtures-src/rle.c`.

## Testing

The smoke test builds the fixtures, runs every helper script, and verifies the example outputs:

```bash
python tests/smoke_test.py       # or: python3 tests/smoke_test.py
```

CI runs the same test on **Ubuntu, macOS, and Windows** with **Python 3.11 and 3.12**. Binary checks run where a C compiler is available and are skipped otherwise.

To regenerate the fixtures locally:

```bash
python fixtures-src/gen_saves.py   # writes ./save-files/
python fixtures-src/gen_pcap.py    # writes ./thermostat.pcap
gcc -O1 -s -o rle fixtures-src/rle.c
```

Both generated paths are gitignored.

To run the real eval cases with Claude Code (billed model runs):

```bash
cd skills/reverse-engineering
claude plugin eval . --allow-tools Write,Edit,Bash --scaffold
```

## Scope and responsible use

Make sure you are allowed to analyze what you point this at; reverse engineering can be restricted by license terms or law where you live.

The skill instructs the assistant to decline:

- defeating licensing, DRM, copy protection, or anti-cheat,
- developing exploits or probing systems the user does not own,
- analyzing, modifying, or improving malware,
- decrypting data the user is not authorized to access.

Secrets found in captures (tokens, cookies, passwords, API keys, device IDs) are redacted from every output, and any client built against a protocol is validated against a capture or a local mock server rather than a live third-party service.

## Contributing

Issues and pull requests are welcome, especially:

- a target type that fails, with a sample you are allowed to share,
- new reference material (firmware, USB/BLE traces, game assets, and similar),
- new eval cases in the same layout as the existing ones.

Keep `SKILL.md` under about 500 lines and put domain detail in `references/`. Helper scripts stay standard-library only so they run anywhere. See [`AGENTS.md`](AGENTS.md) for the full conventions and the cross-file invariants enforced by the smoke test.

```bash
# Before opening a PR
python tests/smoke_test.py
```

## License

[MIT](LICENSE) (c) 2026 Likhon Sheikh - [github.com/sheikhminds](https://github.com/sheikhminds)

Icon from [Flaticon](https://www.flaticon.com/).

<!-- Copyright (c) 2026 Likhon Sheikh - https://github.com/sheikhminds - MIT License -->
