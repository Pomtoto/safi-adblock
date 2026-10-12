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
# without touching the consent dialog, then runs the probe and asserts its result.

set -euo pipefail

# How long we allow the VPN to come up before giving up on the device.
readonly VPN_WAIT_SECONDS="${PROBE_VPN_WAIT:-150}"
# How long the probe itself may take (its sockets use 25s timeouts).
readonly PROBE_RUN_SECONDS="${PROBE_RUN_SECONDS:-120}"

dump_state() {
    echo '--- service state ---'
    adb shell dumpsys activity services app.safi.shield 2>&1 | tail -n 30 || true
    echo '--- connectivity (vpn lines) ---'
    adb shell dumpsys connectivity 2>&1 | grep -iE 'vpn|tun' | head -n 20 || true
    echo '--- logcat (safi / vpn / crashes) ---'
    adb logcat -d 2>/dev/null | grep -iE 'safi|vpn|AndroidRuntime' | tail -n 80 || true
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
export SAFI_KEYSTORE="${RUNNER_TEMP:-/tmp}/probe-signing.jks"
rm -f "${SAFI_KEYSTORE}"
bash tools/build-device-probe.sh || fail "could not build the QA probe APK"
adb install -r artifacts/probe/probe.apk || fail "adb install failed for the QA probe"

# ------------------------------------------------------------- turn the VPN on
# Consent normally needs a tap on a system dialog; the shell may pre-grant it.
adb shell appops set app.safi.shield ACTIVATE_VPN allow || true
adb shell am start -W -n app.safi.shield/.MainActivity >/dev/null || fail "Safi did not start"
sleep 5
# Foreground service start with a visible activity behind it, which Android 12+
# requires for apps that were not just interacted with.
adb shell am start-foreground-service -n app.safi.shield/.ShieldVpnService \
    -a app.safi.shield.START >/dev/null || fail "could not ask the VPN service to start"

deadline=$(( $(date +%s) + VPN_WAIT_SECONDS ))
until adb shell dumpsys activity services app.safi.shield 2>/dev/null | grep -q ShieldVpnService \
   && adb shell dumpsys connectivity 2>/dev/null | grep -qiE '\bvpn\b'; do
    if [ "$(date +%s)" -ge "${deadline}" ]; then
        fail "the VPN did not come up within ${VPN_WAIT_SECONDS}s"
    fi
    sleep 5
done
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
