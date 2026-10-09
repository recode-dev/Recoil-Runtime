#!/usr/bin/env bash
# install_ipa.sh - put RecoilRuntime.dylib into an .ipa and make the app actually load it.
#
#   tools/install_ipa.sh --ipa NullsBrawl.ipa --dylib RecoilRuntime.dylib --out NullsBrawl+recoil.ipa
#
# What it does:
#   1. unpacks the ipa
#   2. copies the dylib into <App>.app/Frameworks/
#   3. adds an LC_LOAD_DYLIB (@executable_path/Frameworks/<name>) to the app binary - this is what
#      makes the loader actually pick it up; tools/inject.py does the Mach-O edit with no external
#      tools. Use --no-lc only if your client already loads everything from a Tweaks/ folder.
#   4. repacks to a new ipa
#
# It does NOT re-sign: editing the header invalidates the signature. Re-sign on macOS with
# `codesign -f -s - --entitlements ent.plist <App>.app` or with `ldid -S<ent> <binary>`, or on any
# OS with `zsign`. The command is printed at the end.
set -euo pipefail

IPA="" ; DYLIB="" ; OUT="" ; APPNAME="" ; DO_LC=1 ; DO_TWEAKS=0
while [ $# -gt 0 ]; do
  case "$1" in
    --ipa) IPA="$2"; shift 2;;
    --dylib) DYLIB="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --app) APPNAME="$2"; shift 2;;
    --no-lc) DO_LC=0; shift;;
    --tweaks) DO_TWEAKS=1; shift;;
    -h|--help) sed -n '2,20p' "$0"; exit 0;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

[ -n "$IPA" ]   || { echo "need --ipa" >&2; exit 2; }
[ -n "$DYLIB" ] || { echo "need --dylib" >&2; exit 2; }
[ -f "$IPA" ]   || { echo "no such ipa: $IPA" >&2; exit 2; }
[ -f "$DYLIB" ] || { echo "no such dylib: $DYLIB" >&2; exit 2; }
[ -n "$OUT" ] || OUT="${IPA%.ipa}+recoil.ipa"
case "$OUT" in /*) ;; *) OUT="$ORIG_PWD/$OUT";; esac   # keep the output out of the temp dir

ORIG_PWD="$(pwd)"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== unpack =="
( cd "$WORK" && unzip -q "$IPA" )
APP=$(find "$WORK/Payload" -maxdepth 1 -name '*.app' | head -1)
[ -n "$APP" ] || { echo "no Payload/*.app in the ipa" >&2; exit 1; }
if [ -z "$APPNAME" ]; then
  APPNAME=$(python3 - "$APP/Info.plist" <<'PY'
import plistlib,sys
with open(sys.argv[1],'rb') as f: d=plistlib.load(f)
print(d.get("CFBundleExecutable",""))
PY
)
fi
[ -n "$APPNAME" ] || { echo "cannot determine the executable name" >&2; exit 1; }
EXE="$APP/$APPNAME"
echo "   app=$APP"
echo "   exe=$APPNAME"

echo "== copy the dylib =="
mkdir -p "$APP/Frameworks"
DYLIB_NAME="$(basename "$DYLIB")"
cp "$DYLIB" "$APP/Frameworks/$DYLIB_NAME"
LOAD_PATH="@executable_path/Frameworks/$DYLIB_NAME"
echo "   $APP/Frameworks/$DYLIB_NAME"
if [ "$DO_TWEAKS" = "1" ]; then
  mkdir -p "$WORK/Tweaks"
  cp "$DYLIB" "$WORK/Tweaks/$DYLIB_NAME"
  echo "   $WORK/Tweaks/$DYLIB_NAME  (for clients whose TweakLoader scans it)"
fi

if [ "$DO_LC" = "1" ]; then
  echo "== add LC_LOAD_DYLIB =="
  python3 "$HERE/inject.py" --target "$EXE" --dylib "$LOAD_PATH"
fi

echo "== repack =="
rm -f "$OUT"
( cd "$WORK" && if [ -d Tweaks ]; then zip -qry "$OUT" Payload Tweaks; else zip -qry "$OUT" Payload; fi )
echo "   $OUT"

cat <<EOF

== NEXT: re-sign, it is mandatory ==
  macOS:  codesign -f -s - --entitlements entitlements.plist "$APP"
  any OS: ldid -S<entitlements> "$EXE"      (or: zsign -k key.p12 -m prov.mobileprovision "$OUT")
Then install the signed ipa (Sideloadly / TrollStore / your own installer).
EOF
