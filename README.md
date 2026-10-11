# Recoil-Runtime

Read-only `.dylib` that shows an alert on entry and scans the loaded game image for offsets,
writing the result to a log. Built by GitHub Actions with Theos for arm64. No hooks, no code patching.

Two jobs, nothing else.

## Build

```
THEOS=/path/to/theos make -j4
```

CI does it on `macos-14` and uploads `RecoilRuntime.dylib`; on a `v*` tag it also attaches it to the release.

## Install (LiveContainer)

1. Open the app's settings, Tweaks, add `RecoilRuntime.dylib`.
2. Launch the game. An alert appears as soon as the tweak loads, then the dylib waits for the guest
   image (`RCL_WAIT_SEC`, default 60s) and scans. A second alert says so if no image turns up.
3. Log lands in `$HOME/Documents` inside the guest container (fallbacks: `$HOME`, `/var/mobile/Documents`,
   `/tmp`). `RCL_LOG_DIR` forces the directory, `RCL_STDERR=1` mirrors to stderr.
   `RCL_IMAGE_MATCH=<substring>` forces which image is scanned.

## Components

| File | Job |
|---|---|
| `rcl_alert.mm` | `alert_show(title, message)` - UIKit alert on the main queue, deduplicated, found through the connected scenes. Called once on entry and once if no target image appears. |
| `rcl_scan.*` | the offset scanner: `[property sites]`, `[column names]`, `[own-character byte flags]`. |
| `rcl_ident.*` | the build stamp (four probes plus a `__text` CRC) that decides which image is the target. |
| `rcl_report.*` | prints the three scanner passes. |
| `rcl_log.*` | the log file itself. |
| `rcl_main.cpp` | constructor, image pick, wait loop, one scan pass. |

## Removed on purpose

The class machinery that used to live here is gone: `rcl_classdump.*` (4.7k lines), `rcl_deep.*` (2.8k),
`rcl_live.*` (4k), `rcl_names.h` + `rcl_names_live.*` (3.2k), `rcl_docdata.h` + `rcl_docgen.*` (3.1k),
`rcl_hook.*` (hooks - this dylib is supposed to install none) and the `rcl_macho` / `rcl_objc` helpers
they pulled in. About 19k lines: class-table discovery, per-class `.md` dumps, `Dumps/All` bundles,
symbol voting, live object-graph walking and the snapshot loop. All of it keyed on build-specific
tables and seeds, none of it needed to read offsets.

## Limits

- The scanner's anchors are discovered from the image (largest arm64 `__TEXT`, `bl`-target scoring);
  they can be overridden with `RCL_PROPGET_RVA`, `RCL_COLNAME_RVA`, `RCL_GETBATTLE_RVA`, `RCL_MIN_TEXT`.
- Naming a field still needs the data schema: the name-to-id link through cache slots was tried and
  did not hold up, so it is not reported.
