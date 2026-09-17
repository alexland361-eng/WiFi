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
echo "built vermagic : $(modinfo -F vermagic ./mac80211_hwsim.ko 2>/dev/null || echo unknown)"
echo "running kernel : $KREL"
echo "module deps    : $(modinfo -F depends ./mac80211_hwsim.ko 2>/dev/null || echo unknown)"

# cfg80211 and mac80211 are =m on this kernel, so their symbols are absent from
# /proc/kallsyms until they are loaded. insmod does not resolve dependencies and
# fails with "Unknown symbol"; installing into the module tree and using modprobe
# lets depmod order them correctly.
echo "--- pre-loading dependencies"
for dep in cfg80211 mac80211; do
  if sudo modprobe "$dep" 2>&1; then
    echo "  $dep loaded"
  else
    echo "  $dep could not be loaded (may be built in, or absent)"
    echo "::notice title=hwsim::modprobe $dep failed on $KREL"
  fi
done
lsmod | grep -E '^(cfg80211|mac80211)\b' || echo "  WARNING: neither dependency visible in lsmod"

DEST="/lib/modules/$KREL/extra"
sudo mkdir -p "$DEST"
sudo cp mac80211_hwsim.ko "$DEST/"
sudo depmod -a "$KREL"
echo "--- installed to $DEST and ran depmod"

if ! INSMOD_OUT=$(sudo modprobe mac80211_hwsim radios="$RADIOS" 2>&1); then
  echo "$INSMOD_OUT"
  # The kernel's own reason (unknown symbol, CRC disagreement, bad vermagic)
  # only appears in dmesg, and job logs are not reachable from here, so both
  # go out as annotations.
  DMESG_OUT=$(sudo dmesg 2>/dev/null | tail -25 || echo "dmesg unavailable")
  echo "--- dmesg tail ---"
  echo "$DMESG_OUT"

  # Pinpoint the exact symbols the module needs but the running kernel lacks.
  if command -v nm >/dev/null 2>&1; then
    MISSING=$(comm -23 \
      <(nm -u ./mac80211_hwsim.ko 2>/dev/null | awk '{print $NF}' | grep -v '^$' | sort -u) \
      <(sudo awk '{print $3}' /proc/kallsyms 2>/dev/null | sort -u) || true)
    echo "--- symbols required by the module but absent from the running kernel ---"
    echo "${MISSING:-  (none - rejection is not a missing symbol)}"
    if [ -n "$MISSING" ]; then
      echo "::error title=load-missing-symbols::$(echo "$MISSING" | tr '\n' ' ' | cut -c1-900)"
    fi
  fi

  note "module load rejected; built vermagic=$(modinfo -F vermagic ./mac80211_hwsim.ko 2>/dev/null || echo unknown) running=$KREL"
  echo "::error title=load-stderr::$(echo "$INSMOD_OUT" | tr '\n' ' ' | cut -c1-900)"
  echo "::error title=load-dmesg::$(echo "$DMESG_OUT" | grep -iE 'hwsim|symbol|version|module' | tr '\n' ' ' | cut -c1-900)"
  fail "modprobe mac80211_hwsim radios=$RADIOS failed"
fi

sleep 2
lsmod | grep -E 'hwsim|mac80211|cfg80211' || echo "WARNING: not visible in lsmod"

COUNT=$(iw dev 2>/dev/null | grep -c 'Interface' || true)
echo "--- interfaces created: $COUNT"
iw dev || true

[ "$COUNT" -ge 1 ] || fail "hwsim loaded but created no wireless interfaces"

note "mac80211_hwsim built out-of-tree and loaded; $COUNT virtual radio(s) available"
echo "=== hwsim ready ==="
