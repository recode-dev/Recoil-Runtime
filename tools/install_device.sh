#!/usr/bin/env bash
# install_device.sh - install RecoilRuntime on a JAILBROKEN device over ssh/scp.
#
#   tools/install_device.sh --device root@192.168.1.50 --dylib RecoilRuntime.dylib \
#                           --bundle-id com.example.brawlstars
#
# Places the dylib where Substrate/ElleKit loads tweaks and writes the matching filter plist.
# Rootless (/var/jb, Dopamine/palera1n) is the default; pass --rootful for the old layout.
# If you built a .deb instead, pass --deb RecoilRuntime.deb and it will dpkg -i it.
set -euo pipefail

DEV="" ; DYLIB="" ; BID="" ; ROOTLESS=1 ; DEB=""
while [ $# -gt 0 ]; do
  case "$1" in
    --device) DEV="$2"; shift 2;;
    --dylib) DYLIB="$2"; shift 2;;
    --bundle-id) BID="$2"; shift 2;;
    --deb) DEB="$2"; shift 2;;
    --rootful) ROOTLESS=0; shift;;
    -h|--help) sed -n '2,12p' "$0"; exit 0;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -n "$DEV" ] || { echo "need --device user@host" >&2; exit 2; }

if [ -n "$DEB" ]; then
  echo "== installing the deb =="
  scp "$DEB" "$DEV:/tmp/"
  ssh "$DEV" "dpkg -i /tmp/$(basename "$DEB") 2>/dev/null || (command -v sileo >/dev/null && echo 'open Sileo and install the file') ; \
              killall -9 SpringBoard 2>/dev/null || true"
  echo "done - respring and launch the game"
  exit 0
fi

[ -n "$DYLIB" ] || { echo "need --dylib (or --deb)" >&2; exit 2; }
[ -n "$BID" ]   || { echo "need --bundle-id" >&2; exit 2; }
[ -f "$DYLIB" ] || { echo "no such dylib: $DYLIB" >&2; exit 2; }

PRE=""; [ "$ROOTLESS" = "1" ] && PRE="/var/jb"
LIBDIR="$PRE/Library/MobileSubstrate/DynamicLibraries"
NAME="$(basename "$DYLIB")"

echo "== target =="
echo "   device : $DEV"
echo "   dir    : $LIBDIR"
echo "   filter : $BID"

PLIST="$NAME.plist"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cat > "$TMP/$PLIST" <<EOF
{
    Filter = { Bundles = ( "$BID" ); };
}
EOF

scp "$DYLIB" "$DEV:/tmp/$NAME"
scp "$TMP/$PLIST" "$DEV:/tmp/$PLIST"
ssh "$DEV" "set -e; mkdir -p '$LIBDIR'; \
            cp '/tmp/$NAME' '$LIBDIR/$NAME'; cp '/tmp/$PLIST' '$LIBDIR/$PLIST'; \
            chmod 755 '$LIBDIR/$NAME'; chown root:wheel '$LIBDIR/$NAME' '$LIBDIR/$PLIST' 2>/dev/null || true; \
            ls -la '$LIBDIR/$NAME' '$LIBDIR/$PLIST'"
echo
echo "installed. respring / relaunch the game, then pull the log:"
echo "  ssh $DEV \"ls -t \\\$(find /var/mobile/Containers/Data/Application -name 'recoil-runtime-*.log' 2>/dev/null) | head -1\""
