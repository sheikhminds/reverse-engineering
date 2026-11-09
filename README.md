# reverse-engineering

A [Claude skill](https://docs.claude.com) that teaches Claude to reverse engineer things it has no source code or documentation for: work out how something works from the outside, then write down what survived testing.

It covers four kinds of target:

| Target | What Claude does with it |
|---|---|
| **Compiled binaries, firmware, bytecode** | Triage, static analysis, reading disassembly, sandboxed differential runs, verifying a reimplementation |
| **Unknown file formats** | Gather samples, find headers, records and checksums, change-one-thing diffing, write a spec **and** a parser that round-trips |
| **Network protocols and undocumented APIs** | Reassemble streams, find framing and envelope, cluster message types, find the checksum, produce a catalog, state machine and decoder |
| **Legacy code and systems** | Inventory, characterization tests, business-rule extraction, data dictionary, risk register |

The method is the same throughout: **observe, hypothesize, test, record**. Every claim is labelled *Confirmed*, *Likely* or *Guess*, with its evidence, so readers know what to rely on.

## Install

**Claude Code / Cowork** (copy the folder):

```bash
git clone https://github.com/sheikhminds/reverse-engineering.git
cp -r reverse-engineering/skills/reverse-engineering ~/.claude/skills/      # personal
# or: cp -r ... your-project/.claude/skills/                                 # one project
```

**Claude.ai**: build a `.skill` file (it is a zip) and upload it where Claude.ai lets you add skills:

```bash
cd reverse-engineering/skills
zip -r reverse-engineering.skill reverse-engineering -x "reverse-engineering/evals/*"
```

Then ask for something like *"what's the format of this file?"*, *"decode this packet capture"*, or *"what does this stripped binary do?"* and attach the material. The skill triggers on the task, not on the words "reverse engineering".

## What's inside

```
skills/reverse-engineering/
├── SKILL.md                 method, scope, workflow, report/spec templates
├── references/
│   ├── binaries.md          binaries, firmware, bytecode
│   ├── file-formats.md      unknown file formats
│   ├── network-protocols.md captures, HAR files, undocumented APIs
│   └── legacy-code.md       systems with no docs
├── scripts/                 standard-library Python, no installs needed
│   ├── triage.py            type, hashes, entropy profile, embedded signatures, strings, ELF/PE headers
│   ├── hexdiff.py           changed regions between two files (differential analysis)
│   ├── probe.py             read the bytes at an offset as every plausible type
│   └── pcap_flows.py        flows and reassembled payloads from a classic .pcap
└── evals/                   three test cases in the layout `claude plugin eval` reads
examples/                    worked results from the three test cases
fixtures-src/                generators and source for the files used by the evals
tests/smoke_test.py          checks the helper scripts end to end
```

The scripts also work on their own (Python 3.11 or newer):

```bash
python3 skills/reverse-engineering/scripts/triage.py some.bin
python3 skills/reverse-engineering/scripts/hexdiff.py before.sav after.sav
python3 skills/reverse-engineering/scripts/probe.py file.bin 0x10
python3 skills/reverse-engineering/scripts/pcap_flows.py capture.pcap --flow 0
```

## Scope and responsible use

Built for interoperability, understanding or documenting software you own or are authorized to analyze, defensive security research, CTFs and education, data recovery, and legacy migration.

The skill tells Claude to decline: defeating licensing, DRM or copy protection; developing exploits or probing systems you don't own; analyzing or modifying malware; and decrypting data you're not authorized to access. Secrets found in captures are redacted from any output. Make sure you're allowed to analyze what you point it at; reverse engineering can be restricted by licence terms or law where you live.

## How it was tested

Three cases, each with a known answer, were run end to end with the skill:

1. a custom save-file format (header, records, CRC-32 trailer),
2. a stripped x86-64 Linux binary (options, exit codes, a hidden run-length cap of 99),
3. a toy TCP sensor protocol in a `.pcap` (framing, CRC-16/CCITT-FALSE, a message split across segments).

All three passed their checks; the results are in [`examples/`](examples/). **These are not blind trials:** the skill and the test inputs were written together and graded by the same author, so treat them as a sanity check, not a benchmark. Real-world files, binaries and captures will be harder. Issues with failing cases are the most useful contribution.

To run the helper-script checks:

```bash
python3 tests/smoke_test.py
```

To run the eval cases with Claude Code (real, billed model runs):

```bash
cd skills/reverse-engineering
claude plugin eval . --allow-tools Write,Edit,Bash --scaffold
```

`evals/*/files/rle` is built from [`fixtures-src/rle.c`](fixtures-src/rle.c) with `gcc -O1 -s`; the saves and the capture come from the other two scripts in `fixtures-src/`.

## Contributing

Issues and pull requests are welcome, especially:

- a target type that fails, with a sample (please make sure you may share it),
- new reference material (for example firmware, USB/BLE traces, game assets),
- new eval cases, in the same layout as the existing ones.

Keep `SKILL.md` under about 500 lines and put domain detail in `references/`. Helper scripts stay standard-library only, so they run anywhere.

## License

[MIT](LICENSE)
