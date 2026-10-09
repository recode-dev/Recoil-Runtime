# Recoil-Runtime

A **read-only** `.dylib` that scans the loaded game image at launch and writes a log of the gameplay
offsets. Built by GitHub Actions with [Theos](https://github.com/theos/theos), installed through
**LiveContainer** (or any tweak loader).

No inline hooks, no code patching, no pointer rewiring. The dylib only reads and logs — which is why
it is safe to drop into LiveContainer and why it needs no `mobilesubstrate` dependency.

```
src --> GitHub runner (macos-14 + Theos) --> RecoilRuntime.dylib --> LiveContainer --> log
```

---

## What it recovers, and how far each part is trusted

| section | what | trust |
|---|---|---|
| `[property sites]` | `field <- property ids`. The engine fills runtime objects through one getter, so every `mov w1,#<id> ; bl <getter> ; str/strb w0,[xN,#<field>]` yields an `id -> field` pair. **This is the useful one**: after a game update the field moves, the property id does not. | **solid** — the id is a literal in the caller, and the store decode is the code unit-tested against hand-checked sites |
| `[column names]` | the data schema's own column-name strings, with the address each was loaded from | **solid as a name list** |
| `[own-character byte flags]` | bytes on `getBattle()+0x28` that gameplay reads as booleans (build 69: `+0x44, +0x14c, +0x2bc, +0x2ec, +0x32e`) | **solid** — register-liveness checked |
| `[reachability]` | how many pointer slots hold each seed, i.e. what a slot hook could observe | **solid** — byte-compared against the image |
| `[loaded images]` | every mapped image >= 512 KB with its `__TEXT` size — shows how LiveContainer maps the guest app | **solid** |

**Deliberately not attempted:** joining a column *name* to a property *id*. Reading the bytes at the
candidate cache slot looked right for a couple of names and then did not hold up — 1482 of 2143 slots
hold "unset" and the rest hold 0 or unrelated data, so the store after the name lookup does not belong
to that cache. Naming a field therefore needs the data schema itself, or a different hook point. This
is written down so it is not "re-discovered" as a success.

## Installing through LiveContainer

1. Let CI build on a tag, or build locally:
   ```
   THEOS=/path/to/theos make -j4 ARCHS="arm64"      # -> RecoilRuntime.dylib
   ```
2. In LiveContainer, open the app's settings -> **Tweaks**, and add `RecoilRuntime.dylib`
   (or drop it into the container's tweak folder). No `.plist` filter is needed.
3. Launch the game. The dylib waits up to 60 s for the guest app to be mapped — LiveContainer injects
   tweaks before the guest image is loaded, so a wait is required.
4. Take the log. `$HOME/Documents` inside the guest container is where it lands; the dylib tries that,
   then `$HOME`, `/var/mobile/Documents`, `/tmp`. Set `RCL_LOG_DIR` to force a directory, or
   `RCL_STDERR=1` to mirror everything to stderr (visible in LiveContainer's console).

`RCL_IMAGE_MATCH=<substring>` forces which image is scanned if the auto-pick is ever wrong. In
LiveContainer the guest app is **not** image 0 — it is a dylib loaded into the host process — so the
dylib picks the target by shape (an `.app/` path, large `__TEXT`, not the host app), not by index.

## Other install paths

**Jailbroken — as a tweak**
```
tools/install_device.sh --device root@<ip> --dylib RecoilRuntime.dylib --bundle-id <id>
```
`make package` also produces a `.deb`.

**Sideloaded IPA — inject the load command**
```
tools/install_ipa.sh --ipa game.ipa --dylib RecoilRuntime.dylib --out game+recoil.ipa
```
Copies the dylib into `<App>.app/Frameworks/`, adds `@executable_path/Frameworks/RecoilRuntime.dylib`
as an `LC_LOAD_DYLIB`, and repacks. Re-signing afterwards is mandatory — the script prints the exact
`codesign` / `ldid` / `zsign` command.

**The client's own TweakLoader** — the binary links `@loader_path/../../Tweaks/TweakLoader.dylib`, so
`--no-lc --tweaks` drops the dylib where that loader looks. The loader's scan directory lives in
`TweakLoader.dylib`, not in the game binary, so confirm the path on your install.

`tools/inject.py` appends the load command inside the header slack and grows `ncmds`/`sizeofcmds`.
Verified on the real image: exactly the two header counters plus the command bytes change, the file
size is untouched, the result still parses as a Mach-O. It refuses when the slack is too small instead
of relocating anything, and it never re-signs.

## Layout

```
Sources/   rcl_scan.*    AArch64 scanner + store-to-W0 decoder   (portable, no OS deps)
           rcl_hook.*    slot search (read-only here); write half is Darwin-only and unused
           rcl_report.*  the report itself                        (portable)
           rcl_log.*     POSIX file logging + stderr mirror       (portable)
           rcl_main.cpp  dylib entry: pick image, wait, scan      (Darwin-guarded)
host/      main.cpp runs the SAME report over a Mach-O file
agent/     arm64_decode.js  the decoder in JS (Frida path), same spec as the C++
test/      decode_test.js   verifies the decoder against the real image
tools/     inject.py  install_ipa.sh  install_device.sh  smoke.sh
```

## Verifying it yourself

```
RCL_BIN=/path/to/attach.txt bash tools/smoke.sh
```
Builds the host scanner with plain `g++`, runs the *same report code* the dylib runs, and checks the
arm64 decoder against hand-verified sites. Everything that could silently produce wrong numbers is
portable C++ precisely so this works without an iOS toolchain.

## Limits worth knowing

* **Seeds are build-69 specific** (`0x8c5130`, `0xafd76c`, `0xbc75e8`, the `__text` bounds) — the one
  thing to update per version. Everything derived from them is not.
* **Nothing can be slot-hooked that lives in no table.** Verified: the property getter and the
  column-name getter have **zero** pointer slots. A virtual target does: `0x7a03a0` has exactly one,
  at `0xfd6c70`. This build does not hook anything anyway.
* **The iOS link happens in CI** (no iOS toolchain here), but the device TUs are Darwin-guarded and
  compile in the host build, so their syntax is covered.
