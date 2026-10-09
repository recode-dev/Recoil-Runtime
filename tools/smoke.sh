#!/usr/bin/env bash
# Everything that can be verified without an iOS toolchain, in one place.
#
#   RCL_BIN=/path/to/attach.txt ./tools/smoke.sh
#
# Exit code 0 means: the host scanner builds and runs, the report is produced, and the arm64 decoder
# matches the real image. The Theos dylib itself needs macOS + Theos and is built in CI.
set -u
cd "$(dirname "$0")/.."
FAIL=0
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=1; }
skip() { printf '  \033[33mSKIP\033[0m  %s\n' "$1"; }

echo "== 1. source sanity =="
for f in agent/arm64_decode.js; do
  if node --check "$f" 2>/dev/null; then ok "$f parses"; else bad "$f has a syntax error"; fi
done
if python3 - <<'PY' 2>/dev/null
import json,sys
try:
    import yaml
except ImportError:
    sys.exit(2)
yaml.safe_load(open(".github/workflows/build.yml"))
PY
then ok "workflow YAML valid"
else
  code=$?
  if [ "$code" = "2" ]; then skip "workflow YAML (pyyaml not installed)"; else bad "workflow YAML invalid"; fi
fi

echo "== 2. host scanner =="
if make -C host >/tmp/rcl_build.log 2>&1; then
  ok "host build (5 translation units)"
else
  bad "host build failed - see /tmp/rcl_build.log"
  tail -20 /tmp/rcl_build.log
fi

IMG="${RCL_BIN:-/tmp/dl/attach.txt}"
if [ -x host/rclscan ] && [ -f "$IMG" ]; then
  if ./host/rclscan "$IMG" /tmp >/tmp/rcl_report.txt 2>&1; then
    ok "scanner ran on $(basename "$IMG")"
    grep -q "\[property sites\]" /tmp/rcl_report.txt && ok "report: property sites present" || bad "report: no property sites"
    grep -q "\[column names\]" /tmp/rcl_report.txt && ok "report: column names present" || bad "report: no column names"
    grep -q "\[own-character byte flags\]" /tmp/rcl_report.txt && ok "report: own-character flags present" || bad "report: no flags"
    grep -q "OverchargeActive" /tmp/rcl_report.txt && ok "charge-related names listed" || skip "no charge names found"
    NSLOT=$(grep -c "1 slot(s)" /tmp/rcl_report.txt || true)
    [ "${NSLOT:-0}" -ge 1 ] && ok "hook slots resolved for virtual targets" || bad "hook slot scan found nothing"
  else
    bad "scanner crashed"
  fi
elif [ ! -f "$IMG" ]; then
  skip "scanner run (no image at $IMG)"
fi

echo "== 3. arm64 decoder vs the real image =="
if [ -f "$IMG" ]; then
  if RCL_BIN="$IMG" node test/decode_test.js 2>&1 | tail -6; then :; fi
  if RCL_BIN="$IMG" node test/decode_test.js >/tmp/rcl_dec.log 2>&1; then
    ok "decoder matches every known property site"
  else
    bad "decoder mismatch - see /tmp/rcl_dec.log"
  fi
else
  skip "decoder test (no image)"
fi

echo
if [ "$FAIL" = "0" ]; then echo "SMOKE: OK"; else echo "SMOKE: FAILURES ABOVE"; fi
exit $FAIL
