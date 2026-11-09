#!/usr/bin/env bash
# Reproduce the key observations in report.md (run in a scratch directory).
set -u
B=${1:?path to rle binary}
strings -a -n 4 "$B" | grep -E "usage|rle-lite|error"
objdump -d -M intel --no-show-raw-insn --start-address=0x1229 --stop-address=0x15d8 "$B" | grep -E "lea +r12,\[rcx\+0x63\]|imul +r14,rax,0x64"
for args in "" "-h" "-V" "aaabcc" "-d 3a1b2c" "a1" "-d a"; do
  timeout 5 env -i "$B" $args >/dev/null 2>&1; echo "rle $args -> exit $?"
done
