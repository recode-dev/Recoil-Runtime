# Recoil-Runtime

Read-only `.dylib` that scans the loaded game image and writes an offsets log.
Built by GitHub Actions with Theos for arm64. No hooks, no code patching.

## Build

```
THEOS=/path/to/theos make -j4
```

CI does it on `macos-14` and uploads `RecoilRuntime.dylib`; on a `v*` tag it also attaches it to the release.

## Install (LiveContainer)

1. Open the app's settings, Tweaks, add `RecoilRuntime.dylib`.
2. Launch the game. The dylib waits for the guest image (`RCL_WAIT_SEC`, default 60s).
3. Everything lands in a single `Dumps` folder inside the guest container: `$HOME/Documents/Dumps`.
   Fallbacks: `RCL_DUMPS_DIR`, `RCL_DOCS_DIR`, `RCL_REPORTS_DIR`, `$RCL_LOG_DIR/Dumps`, `/var/mobile/Documents/Dumps`.
   The log file goes there too unless `RCL_LOG_DIR` is set; `RCL_STDERR=1` mirrors to stderr.
   The whole pass repeats every `RCL_RESCAN_SEC` seconds (default `20`, `0` = single pass) while the
   live sampler keeps running, so the dump keeps growing as the game progresses.

## No hardcoded offsets

Every anchor is discovered from the image itself:

- target image: largest arm64 image by `__TEXT` size, or `RCL_IMAGE_MATCH=<substring>`; `RCL_ALL_IMAGES=1` scans every qualifying image.
- `__TEXT` bounds come from the load commands, not from constants.
- `getProperty` / `getColumnName` / `getBattle` are picked by scoring every `bl` target on its call-site shape; the top candidates and their scores are logged as `[anchor]`.
- the live singleton global and the whole `state -> current -> manager -> array` chain are found by validating pointers inside the data segments.
- class tables come from scanning the data segments for runs of function pointers.

If discovery picks the wrong function, override it: `RCL_PROPGET_RVA`, `RCL_COLNAME_RVA`,
`RCL_GETBATTLE_RVA`, `RCL_HOME_SLOT_RVA`, `RCL_STATE_OFF`, `RCL_CURRENT_OFF`, `RCL_MGR_OFF`,
`RCL_INPUT_OFF`, `RCL_MIN_TEXT`.

## Log contents

- `[loaded images]` - mapped arm64 images with their `__TEXT` size.
- `[anchor]` - candidates per anchor and the selected address.
- `[property sites]` - `field <- property ids`, from `mov w1,#id ; bl <getter> ; str[b] w0,[xN,#field]`.
- `[column names]` - the data schema's column-name strings and the address each was loaded from.
- `[own-character byte flags]` - bytes on `getBattle()+0x28` read as booleans by gameplay.
- `Dumps/` - one `.md` per class, `Unknown/`, `_missing.md`, `_live/`, `_diag.md`, the `_*.md`/`_*.tsv`
  reports, `cache/`, and the flat `All/` copy of every document.

## Limits

- Reference names (`rcl_docdata.h`, `rcl_names.h`; 769 classes / 2090 methods) are a build-69 snapshot and
  act as a dictionary only - nothing is *found* through them. When an image no longer matches them the
  log and `_diag.md` say so, and tables fall back to strings and structure.
- Naming a field still needs the data schema: the name-to-id link through cache slots was tried and
  did not hold up, so it is not reported.
- Discovery is heuristic. Check the `[anchor]` scores and `_diag.md` before trusting a dump.
