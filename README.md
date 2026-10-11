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
disasm/index.md + disasm/fn-<rva>.md
pseudo/index.md + pseudo/fn-<rva>.md
```

- `map-all.md` — the target table: JS offset object, per-target detail and the anchor profiles.
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

## Decoder notes

The A64 decoder covers the integer, branch, system and load/store encodings, the bitfield
aliases (`lsl`/`lsr`/`asr`/`ubfx`/`sbfx`/`bfi`/`bfxil`/`sxtb`/`sxth`/`sxtw`), and the common
scalar FP forms (`fadd`/`fsub`/`fmul`/`fdiv`/`fmax`/`fmin`/`fcmp`/`fabs`/`fneg`/`fsqrt`/`fcvt`/
`frint*`/`scvtf`/`ucvtf`/`fcvtzs`/`fcvtzu`/`fmov`). Anything else is emitted as `.word 0x…` so a
listing never silently loses an instruction. Advanced SIMD is not decoded yet and shows up as
`.word`.

The shipped client is stripped, so function starts are found by the target table and function
ends by a heuristic: a terminator (`ret` / unconditional `b`) past the furthest forward
conditional branch, plus a prologue scan for the next function boundary. Both are visible in the
output as the `insns` / `end` header fields; treat the last few instructions of a function as
uncertain.
