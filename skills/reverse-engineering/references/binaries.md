# Reverse engineering compiled binaries, firmware, and bytecode

Contents: 1. Triage - 2. Static analysis - 3. Reading disassembly - 4. Dynamic analysis (sandboxed) - 5. Non-native targets - 6. Firmware - 7. Verifying your understanding - 8. Reporting

Read `SKILL.md` first for scope and ground rules. If the target looks like malware, or the request is about bypassing licensing or protection, stop: that is outside this skill.

## 1. Triage

```bash
python3 scripts/triage.py target          # type, arch, entropy, strings, header summary
file target
readelf -hS target                        # ELF: header and sections
readelf -d target                         # ELF: needed libraries, rpath
objdump -f target                         # entry point, arch, flags
```

Questions to answer before opening a disassembler:

- **Format and architecture:** ELF, PE, Mach-O, raw blob? x86-64, ARM, MIPS, RISC-V? Endianness? 32 or 64-bit?
- **Stripped?** No symbol table means you'll be naming functions yourself. `nm target` printing "no symbols" confirms it.
- **Packed or protected?** Signs: very high entropy in code sections, few imports, tiny `.text` and huge data, section names like `UPX0`. A plain, documented packer such as UPX on software the user owns can be unpacked with its own tool (`upx -d`). Custom or heavy obfuscation with no stated reason is a cue to re-read the scope section.
- **Linkage:** dynamically linked binaries show their dependencies, which tells you what they can do (sockets, crypto, GUI). Statically linked ones bury library code you'll want to recognize and skip.
- **Language and toolchain hints:** Go (`runtime.` symbols, `.gopclntab`), Rust (`core::`, mangled `_ZN`/`_R` names), C++ (mangled names, vtables), Delphi, .NET, Python-bundled (PyInstaller). Language determines which idioms to expect.

## 2. Static analysis

Work outside in.

**Interfaces first**

```bash
strings -a -n 6 target | less             # ASCII
strings -a -n 6 -el target                # UTF-16LE (common in Windows binaries)
objdump -T target  |  nm -D target        # dynamic symbols: what it imports and exports
readelf --dyn-syms target
```

Strings often give you the command line (`usage:`, `--flag`), file paths, error messages, URLs, format strings, and version banners. Imports tell you the capabilities: `socket`, `connect`, `fopen`, `CreateFileW`, `RegOpenKeyEx`, `EVP_*`.

**Find the entry points**

- Start at `main` if symbols exist. In a stripped ELF, the program entry `_start` passes `main` as the first argument to `__libc_start_main`, so the address loaded into `rdi` just before that call is `main`.
- Exported functions are the interface of a library.
- For callbacks and handlers, follow the registration call (`signal`, `pthread_create`, `RegisterClass`).

**Follow the strings**

Find a string that matters (an error message, a usage line), locate the code that references it, and read outward from there. This is usually the fastest way into an unfamiliar program, and it requires no knowledge of the surrounding code.

**Scripted disassembly** (when `objdump` isn't enough, `pip install --break-system-packages capstone`):

```python
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
code = open("target","rb").read()[OFFSET:OFFSET+LENGTH]   # file offset, not virtual address
md = Cs(CS_ARCH_X86, CS_MODE_64)
for i in md.disasm(code, VADDR):
    print(f"{i.address:#x}: {i.mnemonic} {i.op_str}")
```

For `objdump`: `objdump -d -M intel --no-show-raw-insn target | less`. Add `-s -j .rodata` to dump read-only data and match it against the addresses code refers to.

If Ghidra or radare2/rizin is installed, use them: a headless Ghidra run (`analyzeHeadless`) gives decompiled C for every function, which is much faster to read than raw assembly. See section 3 for how far to trust it.

**Cross-references.** Mapping "who calls this" and "who touches this string or global" is what turns a pile of functions into a program. With only `objdump`, grep the disassembly for the target address: `objdump -d -M intel target | grep -n "0x4010a0"`.

## 3. Reading disassembly

**Calling conventions** (where arguments and results live):

| Platform | Integer/pointer args in order | Return |
|---|---|---|
| x86-64 System V (Linux, macOS) | rdi, rsi, rdx, rcx, r8, r9 | rax |
| x86-64 Windows | rcx, rdx, r8, r9 (+ 32 bytes shadow space) | rax |
| x86-32 cdecl/stdcall | on the stack | eax |
| ARM64 | x0-x7 | x0 |
| ARM32 | r0-r3 | r0 |

**Recognizable shapes**

- Prologue `push rbp; mov rbp, rsp; sub rsp, N` (or ARM `stp x29, x30`): start of a function with locals of size N.
- `call` to a PLT entry (`foo@plt`): a library call. The name is on the call.
- A compare then a conditional jump forms an `if`. A jump back to an earlier address forms a loop.
- A bounded index then `jmp [table + reg*8]` is a `switch`. The table in `.rodata` holds the case targets.
- A loop that loads a byte, compares to zero, and increments is `strlen`-like. Two such pointers compared byte by byte is `strcmp`-like.
- `fs:0x28` (x86-64 Linux) is the stack canary. It marks compiler hardening and is rarely meaningful to the program's logic.
- Large functions full of stack-protector, bounds, and exception scaffolding in Rust/Go/C++ are mostly runtime. Find the user code by its strings and its calls, not by reading from the top.

**Constants that identify algorithms** (useful for documenting what a binary does, so you don't re-derive well-known code):

| Constant | Suggests |
|---|---|
| `0x67452301 0xefcdab89` | MD5 or SHA-1 initial state |
| `0x6a09e667 0xbb67ae85`, `0x428a2f98` | SHA-256 |
| `0xedb88320` or `0x04c11db7` | CRC-32 table or polynomial |
| `0x63 0x7c 0x77 0x7b 0xf2` | AES S-box |
| `0x9e3779b9` | TEA / XTEA / golden-ratio hash |
| `0xcbf29ce484222325` | FNV-1 64-bit offset basis |

**Decompiler output.** Treat it as a hypothesis generator. Types are guessed, signed and unsigned get confused, and optimized loops can look nothing like the source. When a decision depends on a detail (a size, a comparison direction, an off-by-one), check the disassembly.

**Naming.** In stripped code, rename by behavior (`parse_header`, `read_u32_be`) once you've confirmed it, and keep a table of address, name, and evidence. Unconfirmed names get a `maybe_` prefix.

## 4. Dynamic analysis (sandboxed, only when justified)

Static analysis answers most questions without executing anything. Run the target only when behavior can't be determined statically, and only when the program looks benign and the user wants it.

- Use a throwaway working directory, a timeout (`timeout 5 ./target ...`), and no network if you can help it. Never run as root.
- **Differential runs** are the best use of execution: vary one argument or input at a time and compare outputs, exit codes, and files touched. This maps the interface empirically.
- If available: `strace -f -o trace.txt ./target args` for system calls, `ltrace` for library calls, `gdb -batch -ex 'break *ADDR' -ex run -ex 'info registers' ./target` to inspect state at one address.
- Call a function in isolation with `ctypes` against a shared library in the sandbox, to verify a hypothesis about its arguments and results.
- Record exactly what you ran and what you saw. Dynamic results are evidence only if someone can repeat them.

## 5. Non-native targets

These keep far more structure than native code, so decompile rather than disassemble when you can.

| Target | Approach |
|---|---|
| Java `.class` / `.jar` | `javap -c -p -v Foo.class` for bytecode, `unzip -l` for jars; a decompiler such as CFR or Fernflower gives source-like output |
| Python `.pyc` | The header is 16 bytes in 3.7+ (magic, flags, mtime or hash, size). `marshal.loads(data[16:])` gives a code object; `dis.dis(code)` disassembles it. Match the interpreter version to the magic number |
| .NET assemblies | Metadata is rich; use `monodis`, ILSpy, or dnSpy-style tools if present |
| WebAssembly | Magic `\0asm`. `wasm-objdump -x -d` and `wasm2wat` if available |
| Android `.dex` / `.apk` | An `.apk` is a zip. `.dex` begins `dex\n035`. Use `dexdump` or jadx if available |
| Minified or bundled JS | Beautify, then look at string tables and entry points. Source maps, when present, restore names |

## 6. Firmware images

- Find the structure first: scan for magic numbers (filesystems such as squashfs `hsqs`, cramfs, UBI, and compressed streams) with `triage.py` and carve them out by offset with `dd`.
- A raw code image needs a **load address** and **architecture**. For ARM Cortex-M the first two words are the initial stack pointer (into RAM, often `0x2000....`) and the reset vector (an odd address in flash, often `0x0800....`). That pair identifies the image and gives you the base.
- Strings, version banners, and bootloader messages are your best anchors in a flat image.
- Filesystems found inside can be extracted with the normal tools (`unsquashfs`, `tar`, `cpio`), after which the contents are ordinary binaries and config files.

## 7. Verifying your understanding

A hypothesis about a function is only as good as the check you can run on it. Options, from cheapest up:

1. Reimplement the function in Python from your reading and compare against the binary's output on varied inputs, including edge cases (empty, maximum length, boundary values).
2. Emulate just that function (`unicorn` if installable) with chosen register and memory state.
3. Call it via `ctypes` in a sandbox when it's in a shared library.

If your reimplementation agrees on a spread of inputs, call the finding Confirmed and cite those inputs as the evidence.

## 8. Reporting

Use the analysis-report template in `SKILL.md`. For a binary, the Interfaces section should list: command-line options and their effects, input sources (files, stdin, sockets, environment), outputs, files and network endpoints touched, and external dependencies. Put the observed facts first and your interpretation of purpose last.
