#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
#
# Runs inside the GitHub Actions emulator job.
#
# Why this file exists instead of inline YAML: the emulator action does not run its
# `script:` as one shell session. It hands every single line to `/usr/bin/sh -c`, so
# shell variables and `cd` do not survive from one line to the next (and `dash` also
# rejects `set -o pipefail`). Keeping the whole sequence in one bash script is the
# only reliable way to get normal shell behaviour on the device.
#
# It installs the signed release APK, builds and installs the QA probe under a
# separate application id (throwaway key, never the release key), turns the VPN on
# through the app's own button (Android only lets the system - not `adb shell` -
# start a service guarded by BIND_VPN_SERVICE), then runs the probe and asserts
# its result.

set -euo pipefail

readonly TMP="${RUNNER_TEMP:-/tmp}/safi-device"
mkdir -p "$TMP"
# How long we allow the VPN to come up before giving up on the device.
readonly VPN_WAIT_SECONDS="${PROBE_VPN_WAIT:-150}"
# How long the probe itself may take (its sockets use 25s timeouts).
readonly PROBE_RUN_SECONDS="${PROBE_RUN_SECONDS:-120}"

screen_size() {
    adb shell wm size 2>/dev/null | tr -d '\r' | grep -oE '[0-9]+x[0-9]+' | tail -n 1 || echo '320x640'
}

dump_ui() {
    adb shell uiautomator dump /sdcard/safi-ui.xml >/dev/null 2>&1 || return 1
    adb pull /sdcard/safi-ui.xml "$TMP/ui.xml" >/dev/null 2>&1 || return 1
    [ -s "$TMP/ui.xml" ]
}

ui_labels() {
    dump_ui || return 1
    python3 - "$TMP/ui.xml" <<'PY'
import sys, xml.etree.ElementTree as ET
try:
    root = ET.parse(sys.argv[1]).getroot()
except Exception:
    sys.exit(1)
for node in root.iter('node'):
    for key in ('text', 'content-desc'):
        value = (node.get(key) or '').strip()
        if value:
            print(value)
PY
}

# Prints "x y" for the highest-priority candidate label that is on screen, or nothing.
# Nodes whose centre falls outside the display are ignored, because tapping them would
# silently do nothing (they are simply scrolled out of view).
find_label() {
    dump_ui || return 1
    python3 - "$TMP/ui.xml" "$(screen_size)" "$@" <<'PY'
import sys, xml.etree.ElementTree as ET
path, size, wanted = sys.argv[1], sys.argv[2], sys.argv[3:]
try:
    width, height = (int(v) for v in size.lower().split('x'))
except Exception:
    width, height = 320, 640
try:
    root = ET.parse(path).getroot()
except Exception:
    sys.exit(1)
best = None
for node in root.iter('node'):
    blob = '%s %s' % (node.get('text') or '', node.get('content-desc') or '')
    if not blob.strip():
        continue
    bounds = (node.get('bounds') or '').strip()
    try:
        first, second = bounds.strip('[]').split('][')
        x1, y1 = (int(v) for v in first.split(','))
        x2, y2 = (int(v) for v in second.split(','))
    except Exception:
        continue
    x, y = (x1 + x2) // 2, (y1 + y2) // 2
    if not (0 <= x < width and 0 <= y < height):
        continue
    for rank, needle in enumerate(wanted):
        if needle in blob and (best is None or rank < best[0]):
            best = (rank, x, y)
if best:
    print('%d %d' % best[1:])
PY
}

tap_label() {
    local coords
    coords="$(find_label "$@" || true)"
    [ -n "$coords" ] || return 1
    # shellcheck disable=SC2086
    adb shell input tap $coords >/dev/null
    echo "tapped a button at ${coords} (looking for: ${1})"
}

# A real tunnel, not just the VpnNetworkProvider entry that is always listed.
vpn_up() {
    adb shell dumpsys activity services app.safi.shield 2>/dev/null | grep -q 'ShieldVpnService.*isForeground=true\|isForeground=true.*ShieldVpnService' \
        && adb shell dumpsys connectivity 2>/dev/null | grep -qiE 'ni\{VPN|Transports: VPN'
}

dump_state() {
    echo '--- what was on screen ---'
    ui_labels 2>/dev/null | head -n 40 || true
    echo '--- service state ---'
    adb shell dumpsys activity services app.safi.shield 2>&1 | tail -n 25 || true
    echo '--- connectivity (vpn lines) ---'
    adb shell dumpsys connectivity 2>&1 | grep -iE 'ni\{VPN|Transports: VPN' | head -n 5 || true
    echo '--- logcat (safi / vpn / crashes) ---'
    adb logcat -d 2>/dev/null | grep -iE 'safi|vpn|AndroidRuntime' | tail -n 60 || true
    echo '--- end of state dump ---'
}

fail() { echo "DEVICE PROBE FAILED: $*" >&2; dump_state; exit 1; }

# ---------------------------------------------------------------- install the app
APK="$(ls release-output/*.apk 2>/dev/null | head -n 1 || true)"
if [ -z "${APK}" ] || [ ! -f "${APK}" ]; then
    fail "no APK found in release-output/ (did the build job upload the artifact?)"
fi
echo "Installing ${APK}"
adb install -r "${APK}" || fail "adb install failed for ${APK}"

# ------------------------------------------- build and install the QA probe app
export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
export ANDROID_BUILD_TOOLS="${ANDROID_BUILD_TOOLS:-35.0.0}"
export SAFI_KEYSTORE="$TMP/probe-signing.jks"
rm -f "${SAFI_KEYSTORE}"
bash tools/build-device-probe.sh || fail "could not build the QA probe APK"
adb install -r artifacts/probe/probe.apk || fail "adb install failed for the QA probe"

# ------------------------------------------------------------- turn the VPN on
# `appops set ... ACTIVATE_VPN allow` removes the consent dialog. The service itself
# still has to be started by the app: `adb shell` (uid 2000) may not start a service
# guarded by android.permission.BIND_VPN_SERVICE - only the system and the app itself
# are allowed - so pressing the button in the app is both the honest path and the one
# a real user takes.
adb shell appops set app.safi.shield ACTIVATE_VPN allow || true
# Safi asks for POST_NOTIFICATIONS on first start. Pre-granting it keeps the system
# permission dialog (which blocked the screen for the whole run once) out of the way.
adb shell pm grant app.safi.shield android.permission.POST_NOTIFICATIONS || true
adb shell appops set app.safi.shield POST_NOTIFICATION allow || true
adb shell am start -W -n app.safi.shield/.MainActivity >/dev/null || fail "Safi did not start"
sleep 4

# First run shows the disclosure dialog; a private-DNS warning may follow; Android 13+
# may ask to add the Quick Settings tile; the VPN consent dialog appears when the appop
# did not take. Any of them can be in front, so tap whichever button is on screen, and
# scroll the page when the button we want is simply further down.
for attempt in $(seq 1 10); do
    vpn_up && break
    if tap_label "موافق، متابعة" "Allow" "تشغيل مع التنبيه" "تشغيل الحماية" \
                 "إضافة" "Add" "ADD" "OK" "موافق"; then
        sleep 3
        continue
    fi
    adb shell input swipe 160 460 160 200 >/dev/null 2>&1 || true
    sleep 1
done

if ! vpn_up; then
    deadline=$(( $(date +%s) + VPN_WAIT_SECONDS ))
    while ! vpn_up; do
        if [ "$(date +%s)" -ge "${deadline}" ]; then
            fail "the VPN tunnel did not come up within ${VPN_WAIT_SECONDS}s"
        fi
        sleep 5
    done
fi
echo "VPN service is running; waiting a few seconds for DNS forwarding to settle."
sleep 10

# ------------------------------------------------------------------ run the probe
adb logcat -c || true
adb shell am start -n app.safi.probe/.ProbeActivity >/dev/null || fail "probe activity did not start"

deadline=$(( $(date +%s) + PROBE_RUN_SECONDS ))
while true; do
    adb logcat -d -s SafiProbe:I 2>/dev/null > probe-output.txt || true
    grep -q 'DEVICE TESTS COMPLETE' probe-output.txt && break
    if [ "$(date +%s)" -ge "${deadline}" ]; then
        echo 'The probe never reported a final result:'
        cat probe-output.txt || true
        fail "the probe did not finish within ${PROBE_RUN_SECONDS}s"
    fi
    sleep 5
done

cat probe-output.txt
if ! grep -q 'DEVICE TESTS COMPLETE: 8 passed, 0 failed' probe-output.txt; then
    fail "the probe reported passing checks other than the expected 8"
fi

# The probe talks to the VPN with its own sockets only while it is foregrounded;
# stop it so a leftover activity cannot interfere with later steps.
adb shell am force-stop app.safi.probe || true
echo "DEVICE PROBE OK: 8 checks passed with the VPN running."
