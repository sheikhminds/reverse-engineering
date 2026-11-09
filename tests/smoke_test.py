#!/usr/bin/env python3
# Copyright (c) 2026 Likhon Sheikh <https://github.com/sheikhminds>
# SPDX-License-Identifier: MIT
"""End-to-end check of the helper scripts. Standard library only. Run: python3 tests/smoke_test.py"""
import json, os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPTS = os.path.join(ROOT, "skills", "reverse-engineering", "scripts")
FIX = os.path.join(ROOT, "fixtures-src")
failures = []

def run(*args, cwd=None):
    p = subprocess.run([sys.executable, *args], capture_output=True, text=True, cwd=cwd, timeout=60)
    return p.returncode, p.stdout + p.stderr

def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        failures.append(name)
        if detail:
            print("     " + detail.replace("\n", "\n     ")[:600])

tmp = tempfile.mkdtemp()
try:
    for gen in ("gen_saves.py", "gen_pcap.py"):
        rc, out = run(os.path.join(FIX, gen), cwd=tmp)
        check(f"fixture generator {gen} runs", rc == 0, out)
    one, later = (os.path.join(tmp, "save-files", n) for n in ("one-player.sav", "one-player-later.sav"))
    cap = os.path.join(tmp, "thermostat.pcap")

    rc, out = run(os.path.join(SCRIPTS, "triage.py"), one, "--json")
    data = json.loads(out) if rc == 0 else {}
    check("triage --json reports size 29 and a sha256", data.get("size") == 29 and len(data.get("sha256", "")) == 64, out)
    rc, out = run(os.path.join(SCRIPTS, "triage.py"), one)
    check("triage text output shows the GSAV magic bytes", rc == 0 and "GSAV" in out, out)

    rc, out = run(os.path.join(SCRIPTS, "hexdiff.py"), one, later)
    check("hexdiff finds 4 changed regions (timestamp, level, hp+gold, crc)", rc == 0 and "4 region(s)" in out, out)

    rc, out = run(os.path.join(SCRIPTS, "probe.py"), "-", "0", "--hex", "70 4e 0f 69")
    check("probe reads 70 4e 0f 69 as a 2025 unix timestamp", rc == 0 and "unix s: 2025-11-08" in out, out)

    rc, out = run(os.path.join(SCRIPTS, "pcap_flows.py"), cap)
    check("pcap_flows lists one flow", rc == 0 and "1 flow(s)" in out, out)
    rc, out = run(os.path.join(SCRIPTS, "pcap_flows.py"), cap, "--flow", "0")
    check("pcap_flows reassembles 57 and 88 bytes", rc == 0 and "A->B: 57 bytes" in out and "B->A: 88 bytes" in out, out)

    ex = os.path.join(ROOT, "examples")
    rc, out = run(os.path.join(ex, "protocol-capture", "decode_thermostat.py"), cap)
    check("example decoder prints 3 readings with valid checksums",
          rc == 0 and out.count("READING") == 3 and "all checksums valid" in out and "temp=-3.5" in out, out)
    rc, out = run("-c", "import sys; sys.path.insert(0, sys.argv[1]); import gsav, glob;"
                        "[gsav.serialize(gsav.parse(open(p,'rb').read()))==open(p,'rb').read() or sys.exit(1)"
                        " for p in glob.glob(sys.argv[2]+'/save-files/*.sav')]", os.path.join(ex, "save-file-format"), tmp)
    check("example save parser round-trips every sample", rc == 0, out)

    if shutil.which("gcc"):
        exe = os.path.join(tmp, "rle")
        subprocess.run(["gcc", "-O1", "-s", "-o", exe, os.path.join(FIX, "rle.c")], check=True)
        rc, out = run(os.path.join(SCRIPTS, "triage.py"), exe, "--json")
        elf = json.loads(out).get("elf", {}) if rc == 0 else {}
        check("triage parses the ELF and reports it stripped", elf.get("stripped") is True, out)
        p = subprocess.run([exe, "aaabcc"], capture_output=True, text=True, timeout=5)
        check("fixture binary encodes aaabcc as 3a1b2c", p.stdout.strip() == "3a1b2c")
    else:
        print("SKIP binary checks (no gcc)")
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{len(failures)} failure(s)" if failures else "\nall checks passed")
sys.exit(1 if failures else 0)
