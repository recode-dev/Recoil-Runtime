# Recoil-Runtime

Runtime offset dumper for the Nulls Brawl client. Injected as a dylib, it finds the engine
anchors, resolves the target table against live memory, disassembles the resolved functions and
writes everything into the app's Documents as a folder tree of markdown files.

MIT licensed. See `LICENSE`.

## Layout

```
src/core   anchors, scanners, target resolver, disassembler, pseudocode, report, dump writers
src/scan   vtable / ctor / leaf-getter scanners
src/utils  alert, document output
tools      signature helpers
```

## Output

`<Documents>/RecoilRuntime/`

```
index.md
anchors/anchors.md
map-all.md
objc.md
disasm/index.md + disasm/fn-<rva>.md
pseudo/index.md + pseudo/fn-<rva>.md
```

- `map-all.md` — the target table: JS offset object, per-target detail and the anchor profiles.
- `objc.md` — the ObjC runtime walked in-process (`objc_copyClassList` +
  `class_copyMethodList`), filtered to `IMP`s that land inside the target image: every name the
  stripped client still exposes, as `rva -> -[Class sel]` / `+[Class sel]`. These names also feed
  the disassembly and pseudocode, so calls and tail calls into engine methods get real names
  instead of `sub_<rva>`.
- `disasm/fn-<rva>.md` — full A64 listing (`rva`, raw word, mnemonic, resolved branch/call name)
  plus the call sites of that function.
- `pseudo/fn-<rva>.md` — pseudocode for the same function: register-accurate basic statements,
  `if`/`goto` from the decoded condition flags, memory access widths, and `+off matches <key>`
  hints where a constant matches a resolved field offset.

Everything is read through the `Image` abstraction, so the same code paths run against live
process memory. Nothing is resolved by reading a file off disk.

## Build

```
make ARCHS=arm64 FINALPACKAGE=1
```

The dylib lands in `.theos/`; `make` also copies it next to the project root for CI artifacts.

## Env

| var | meaning |
|---|---|
| `RCL_WAIT_SEC` | how long to wait for the target image (default 60) |
| `RCL_MIN_TEXT` | `__TEXT` size threshold for image selection (default `0x80000`) |
| `RCL_IMAGE_MATCH` | only consider images whose path contains this |
| `RCL_ALL_IMAGES` | scan every image above the threshold, not just the app |
| `RCL_LOG_DIR` | override the output directory |
| `RCL_DELAY_MS` | delay before the first pass |
| `RCL_DISASM_MAX` | how many resolved functions to disassemble (default 96) |
| `RCL_DISASM_RVAS` | extra RVAs to disassemble regardless of the target table (`0x1234 0x5678`) |
| `RCL_DISASM_INSNS` | instruction cap per function (default 2000) |
| `RCL_PSEUDO_LINES` | pseudocode statement cap per function (default 400) |
| `RCL_OBJC_MAX` | rows written to `objc.md` (default 4000) |

## Decoder notes

The A64 decoder covers the integer, branch, system and load/store encodings, the bitfield
aliases (`lsl`/`lsr`/`asr`/`ubfx`/`sbfx`/`bfi`/`bfxil`/`sxtb`/`sxth`/`sxtw`), the load/store
exclusive and acquire/release families (`ldxr`/`stxr`/`ldaxr`/`stlxr`/`ldxp`/`stxp`/`ldar`/`stlr`
with their byte/half forms), and the scalar FP forms (`fadd`/`fsub`/`fmul`/`fdiv`/`fmax`/`fmin`/
`fmadd`…/`fcmp`/`fcsel`/`fabs`/`fneg`/`fsqrt`/`fcvt`/`frint*`/`scvtf`/`ucvtf`/`fcvtzs`/`fcvtzu`/
`fmov`, including the FP-immediate form). Anything else is emitted as `.word 0x…` so a listing
never silently loses an instruction.

Not decoded yet, and therefore visible as `.word`: advanced SIMD (vector arithmetic, `movi`,
`dup`, `mov` between vector registers), SVE, the LSE atomics (`ldadd`/`swp`/`cas`) and
`ccmp`/`ccmn`.

The shipped client is stripped, so function starts are found by the target table and function
ends by a heuristic: a terminating instruction (`ret`, a tail call `b` leaving the function, or
any terminator past the furthest forward conditional branch) plus a prologue scan for the next
function boundary. Both are visible in the output as the `insns` / `end` header fields; treat the
last few instructions of a function as uncertain.

## Verification

`tools/decode_check.py` is a differential test for the decoder. It samples A64 words out of a
Mach-O `__TEXT`, decodes them with both the Recoil decoder and capstone, and reports decode gaps
and real mismatches (alias spellings and number formatting are normalised away). It is a
development tool and is not part of the dylib build.

```
pip install capstone
python3 tools/decode_check.py <macho> [samples] [stride]
```

Measured against the Nulls client binary, 20000 sampled `__TEXT` words:

| metric | value |
|---|---|
| recoil decodes | 90.1% of the words capstone decodes |
| emitted as `.word` | 9.9%, of which ~6.7 points is data (`__TEXT` holds string/pointer data between functions) |
| mnemonic mismatch | 0.6%, of which most is data that happens to form a valid encoding |
| operand mismatch | 0.2% (formatting: float display, decimal vs hex offsets) |

Every load/store, bitfield, branch, exclusive/atomic and scalar-FP mismatch this gate reported has
been fixed; what is left is the SIMD/SVE area listed above.
