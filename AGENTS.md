# AGENTS.md

Guidance for AI agents working in this repository. Read this before editing.

## What this repo is

A [Claude skill](https://docs.claude.com) that teaches an assistant to reverse engineer
compiled binaries, unknown file formats, network protocols, and legacy systems. It is
mostly prose plus four standard-library Python helper scripts.

There is no application, package manager, or build step. The "product" is
`skills/reverse-engineering/`, and the quality gate is `tests/smoke_test.py`.

## Layout

```
skills/reverse-engineering/
├── SKILL.md                 entry point: method, scope, workflow, report templates
├── references/              per-domain depth (binaries, file-formats, network-protocols, legacy-code)
├── scripts/                 triage.py, hexdiff.py, probe.py, pcap_flows.py
└── evals/                   three eval cases (case.yaml + prompt.md + files/ + graders/)
examples/                    worked deliverables for the three evals
fixtures-src/                generators (gen_saves.py, gen_pcap.py) and rle.c
tests/smoke_test.py          end-to-end check of scripts + examples
.github/workflows/test.yml   runs the smoke test on Ubuntu + Python 3.12
```

## Commands

```bash
# Test (the only automated check). Use `python` on Windows, `python3` elsewhere.
python tests/smoke_test.py

# Run helper scripts directly
python skills/reverse-engineering/scripts/triage.py <file> [--json]
python skills/reverse-engineering/scripts/hexdiff.py a b
python skills/reverse-engineering/scripts/probe.py <file> <offset> [--hex "de ad"]
python skills/reverse-engineering/scripts/pcap_flows.py <cap.pcap> [--flow N] [--raw prefix]

# Regenerate fixtures (writes ./save-files/ and ./thermostat.pcap; both are gitignored)
python fixtures-src/gen_saves.py
python fixtures-src/gen_pcap.py
gcc -O1 -s -o rle fixtures-src/rle.c        # rebuild the eval binary

# Run evals with Claude Code (real, billed model runs)
cd skills/reverse-engineering
claude plugin eval . --allow-tools Write,Edit,Bash --scaffold

# Build the uploadable .skill (zip); evals are excluded
cd skills
zip -r reverse-engineering.skill reverse-engineering -x "reverse-engineering/evals/*"
```

There is no linter, formatter, type checker, or dependency manifest. Do not add one
without a concrete reason; portability is deliberate.

## Conventions that matter

### Skill docs
- Keep `SKILL.md` under about 500 lines. Put domain detail in `references/` and link to it.
- Preserve the scope/ground rules: decline defeating licensing/DRM/copy protection,
  developing exploits or probing unauthorized systems, analyzing/improving malware, and
  decrypting data the user isn't authorized to access. Don't remove or soften these.
- Every claim in docs, specs, and reports uses the confidence vocabulary
  **Confirmed / Likely / Guess**, with evidence. Keep that distinction explicit.
- Deliverables follow the templates in `SKILL.md` (analysis report, format/protocol spec,
  working artifacts). Examples in `examples/` are the reference style.

### Helper scripts (`skills/reverse-engineering/scripts/`)
- **Standard library only.** No third-party imports; they must run anywhere.
- Python 3.11+ (the code uses `datetime.UTC`, `int.bit_count`-era features, etc.).
- Use `argparse`, provide `--help`, and support `--json` for machine-readable output where
  it exists today.
- Keep the trailing `signal.signal(signal.SIGPIPE, signal.SIG_DFL)` idiom for POSIX piping,
  guarded with `if hasattr(signal, "SIGPIPE")` for Windows (see SIGPIPE handling).
- Output goes to stdout; errors to stderr; return non-zero on failure.

### Evals (`skills/reverse-engineering/evals/<case>/`)
- Layout is fixed: `case.yaml`, `prompt.md`, `place-files.sh`, `files/`, `graders/NN-*.md`.
- `case.yaml`: `schema_version: "1.1"`, `name`, `expected_outcome`, `context.scaffold_script`.
- `prompt.md` frontmatter: `tags`, `max_turns`, `timeout_seconds`, `allowed_tools`.
- Graders are Markdown with frontmatter `type: llm`, `focus: trace`, `weight: 1`, then one
  verifiable assertion in prose. Number them `01-`, `02-`, ... and keep assertions specific.
- `place-files.sh` copies `files/.` into the working directory. Keep it POSIX shell.

### Fixtures and examples
- `fixtures-src/gen_saves.py` and `gen_pcap.py` are the source of truth for sample data.
  The checked-in eval copies live under `evals/*/files/`; the generated copies are ignored.
- `examples/` are worked answers that mirror the evals. Keep them consistent with fixtures.
- `examples/stripped-binary/repro.sh` assumes a POSIX shell and a local `rle` binary.

## Cross-file invariants (read before changing fixtures, scripts, or examples)

`tests/smoke_test.py` hard-codes expected values. If you change a fixture, script, or
example, update the test or the expectations together. It currently asserts, among others:

- `one-player.sav` is 29 bytes; `triage --json` reports `size: 29` and a 64-char sha256.
- `triage` text output contains `GSAV`.
- `hexdiff.py one-player.sav one-player-later.sav` reports `4 region(s)`.
- `probe.py - 0 --hex "70 4e 0f 69"` prints `unix s: 2025-11-08`.
- `pcap_flows.py` reports `1 flow(s)`, and flow 0 reassembles `A->B: 57 bytes` / `B->A: 88 bytes`.
- `examples/protocol-capture/decode_thermostat.py` prints 3 `READING`s, `all checksums valid`,
  and `temp=-3.5`.
- `examples/save-file-format/gsav.py` round-trips every generated `.sav`.
- The ELF from `rle.c` reports `stripped: true`, and `rle aaabcc` prints `3a1b2c`.

CI runs the smoke test on Ubuntu, macOS, and Windows with Python 3.11 and 3.12. Binary
checks run wherever a compiler (`gcc`) is present (Ubuntu runners have one) and are
skipped elsewhere.

## SIGPIPE handling

Every helper script ends with a `signal.signal(signal.SIGPIPE, signal.SIG_DFL)` call for
quiet POSIX piping. It is guarded with `if hasattr(signal, "SIGPIPE")` because the constant
does not exist on native Windows. Keep the guard when editing scripts; do not remove the
behavior.

## Copyright and licensing

Copyright (c) 2026 Likhon Sheikh - https://github.com/sheikhminds. The project is MIT
licensed. Source files carry a short SPDX header, Markdown/YAML docs carry a notice, and
binary fixtures (`*.sav`, `*.pcap`, the prebuilt `rle`) are left untouched because a text
header would corrupt them.

## Style

- Match surrounding prose: direct, evidence-first, no marketing language.
- Markdown: one sentence per line is not required; keep paragraphs readable.
- Code: no explanatory comments unless they add non-obvious context; docstrings are fine.
- Don't commit generated files (`__pycache__/`, `*.pyc`, `*.skill`, `/save-files/`,
  `/thermostat.pcap`, `.DS_Store`).
- Do not commit unless explicitly asked.

<!-- Copyright (c) 2026 Likhon Sheikh - https://github.com/sheikhminds - MIT License -->
