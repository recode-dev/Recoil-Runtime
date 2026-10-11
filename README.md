# Recoil-Runtime

Runtime offset dumper for the Nulls Brawl client. Injected as a dylib, it finds the engine
anchors, dumps the class/vtable/ctor surface and writes everything into the app's Documents as
a folder tree of markdown files.

MIT licensed. See `LICENSE`.

## Layout

```
src/core   anchors, scanners, report, target resolver, dump writers, entry point
src/scan   vtable / ctor / leaf-getter scanners
src/utils  alert, document output
tools      signature helpers
```

## Output

`<Documents>/RecoilRuntime/`

```
index.md
anchors/anchors.md
properties/fields.md
columns/columns.md
vtables/index.md + vtables/vtable-<addr>.md
ctors/index.md + ctors/ctor-<addr>.md
targets/resolved.md
missing/<key>.md
```

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
