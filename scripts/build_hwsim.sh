#!/usr/bin/env bash
#
# Build and load mac80211_hwsim out-of-tree.
#
# Needed because the Azure-tuned kernels on GitHub-hosted runners are built
# with cfg80211 and mac80211 but without CONFIG_MAC80211_HWSIM, and no distro
# package supplies a module the kernel config never built. The driver itself
# includes only public kernel headers (<net/mac80211.h>, <linux/*>) and no
# internal mac80211 headers, so it compiles against linux-headers and links
# against the running kernel's exported symbols.
#
# Usage: scripts/build_hwsim.sh [kernel-release]   (defaults to `uname -r`)
#
set -uo pipefail

KREL="${1:-$(uname -r)}"
RADIOS="${RADIOS:-2}"
WORK="${RUNNER_TEMP:-/tmp}/hwsim-build"

note() { echo "::notice title=hwsim::$*"; }
fail() { echo "::error title=hwsim::$*"; echo "FATAL: $*" >&2; exit 1; }

echo "=== building mac80211_hwsim for kernel $KREL ==="

[ -d "/lib/modules/$KREL" ] || fail "no /lib/modules/$KREL"

echo "--- installing build dependencies"
sudo apt-get install -y build-essential "linux-headers-$KREL" >/dev/null 2>&1 \
  || sudo apt-get install -y build-essential linux-headers-generic >/dev/null 2>&1 \
  || fail "could not install kernel headers for $KREL"

KDIR="/lib/modules/$KREL/build"
[ -d "$KDIR" ] || fail "kernel build tree $KDIR missing after header install"

rm -rf "$WORK"
mkdir -p "$WORK"
cd "$WORK" || fail "cannot enter $WORK"

# Ubuntu's 6.17.0-1022-azure derives from upstream v6.17; take the series tag.
SERIES="$(echo "$KREL" | grep -oE '^[0-9]+\.[0-9]+' || true)"
[ -n "$SERIES" ] || fail "cannot parse kernel series from $KREL"

BASE="https://raw.githubusercontent.com/torvalds/linux"
DIR="drivers/net/wireless/virtual"

fetch_source() {
  local ref="$1"
  echo "--- fetching driver source at $ref"
  curl -fsSL --retry 3 --max-time 60 -o mac80211_hwsim.c "$BASE/$ref/$DIR/mac80211_hwsim.c" \
    && curl -fsSL --retry 3 --max-time 60 -o mac80211_hwsim.h "$BASE/$ref/$DIR/mac80211_hwsim.h"
}

if ! fetch_source "v$SERIES"; then
  echo "v$SERIES unavailable; falling back to master (API drift possible)"
  note "fetching hwsim from master because v$SERIES was not found"
  fetch_source master || fail "could not download mac80211_hwsim source"
fi

echo "source: $(wc -l < mac80211_hwsim.c) lines, includes:"
grep '^#include' mac80211_hwsim.c | tr '\n' ' '
echo

# kbuild needs literal tabs in the recipe.
printf 'obj-m += mac80211_hwsim.o\nall:\n\t$(MAKE) -C %s M=$(CURDIR) modules\n' "$KDIR" > Makefile
cat Makefile

echo "--- compiling"
if ! make 2>&1 | tail -40; then
  note "out-of-tree build failed; see log above"
  fail "compilation against $KDIR failed"
fi

[ -f mac80211_hwsim.ko ] || fail "build produced no mac80211_hwsim.ko"
echo "built: $(ls -l mac80211_hwsim.ko | awk '{print $5}') bytes"
modinfo ./mac80211_hwsim.ko 2>/dev/null | grep -E '^(vermagic|depends|license):' || true

echo "--- loading with radios=$RADIOS"
if ! sudo insmod ./mac80211_hwsim.ko radios="$RADIOS" 2>&1; then
  note "insmod failed - likely symbol or vermagic mismatch with $KREL"
  fail "insmod mac80211_hwsim.ko failed"
fi

sleep 2
lsmod | grep -E 'hwsim|mac80211|cfg80211' || echo "WARNING: not visible in lsmod"

COUNT=$(iw dev 2>/dev/null | grep -c 'Interface' || true)
echo "--- interfaces created: $COUNT"
iw dev || true

[ "$COUNT" -ge 1 ] || fail "hwsim loaded but created no wireless interfaces"

note "mac80211_hwsim built out-of-tree and loaded; $COUNT virtual radio(s) available"
echo "=== hwsim ready ==="
