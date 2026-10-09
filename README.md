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
2. Launch the game. The dylib waits up to 60s for the guest image.
3. Log lands in `$HOME/Documents` inside the guest container (fallbacks: `$HOME`, `/var/mobile/Documents`, `/tmp`).
   `RCL_LOG_DIR` forces the directory, `RCL_STDERR=1` mirrors to stderr.
   `RCL_IMAGE_MATCH=<substring>` forces which image is scanned.

## Log contents

- `[loaded images]` - every mapped image over 512KB with its `__TEXT` size.
- `[property sites]` - `field <- property ids`, from `mov w1,#id ; bl <getter> ; str[b] w0,[xN,#field]`.
- `[column names]` - the data schema's column-name strings and the address each was loaded from.
- `[own-character byte flags]` - bytes on `getBattle()+0x28` read as booleans by gameplay.

## Limits

- Seeds (`0x8c5130`, `0xafd76c`, `0xbc75e8`, `__text` bounds) are build-69 specific.
- Naming a field still needs the data schema: the name-to-id link through cache slots was tried and
  did not hold up, so it is not reported.
