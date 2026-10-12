#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Optional QA app, a separate UID. NOT part of the Safi release APK.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:?Android SDK required}}"
BT="${SDK}/build-tools/${ANDROID_BUILD_TOOLS:-35.0.0}"; API="${SDK}/platforms/android-35/android.jar"
WORK="$ROOT/artifacts/probe"; mkdir -p "$WORK"/{classes,dex}
cat > "$WORK/AndroidManifest.xml" <<'EOF'
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="app.safi.probe"><uses-sdk android:minSdkVersion="26" android:targetSdkVersion="28"/><uses-permission android:name="android.permission.INTERNET"/><application android:label="Safi Test Probe" android:theme="@android:style/Theme.Material.Light.NoActionBar"><activity android:name=".ProbeActivity" android:exported="true"><intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity></application></manifest>
EOF
"$BT/aapt2" link --manifest "$WORK/AndroidManifest.xml" -I "$API" -o "$WORK/probe-unsigned.apk"
javac -J-Xmx96m --release 8 -encoding UTF-8 -classpath "$API" -d "$WORK/classes" "$ROOT/tests/device/ProbeActivity.java" "$ROOT/app/src/main/java/app/safi/shield/DnsCodec.java"
jar cf "$WORK/classes.jar" -C "$WORK/classes" .
java -Xmx96m -cp "$BT/lib/d8.jar" com.android.tools.r8.D8 --min-api 26 --lib "$API" --output "$WORK/dex" "$WORK/classes.jar"
(cd "$WORK/dex" && zip -q "$WORK/probe-unsigned.apk" classes.dex)
"$BT/zipalign" -f 4 "$WORK/probe-unsigned.apk" "$WORK/probe-aligned.apk"
KEY="${SAFI_KEYSTORE:-$HOME/.cache/safi-probe.jks}"
export SAFI_KEY_PASS="${SAFI_KEY_PASS:-android}"
ALIAS="${SAFI_KEY_ALIAS:-safi}"
if [[ ! -f "$KEY" ]]; then
 mkdir -p "$(dirname "$KEY")"
 # The probe is a QA tool with no privileges of its own: a throwaway local key is enough,
 # and CI must never touch the real application signing key for it.
 keytool -genkeypair -keystore "$KEY" -storepass:env SAFI_KEY_PASS -keypass:env SAFI_KEY_PASS -alias "$ALIAS" \
  -keyalg RSA -keysize 2048 -validity 3650 -dname 'CN=Safi QA Probe, O=Safi, C=IQ' -noprompt
fi
"$BT/apksigner" sign --ks "$KEY" --ks-key-alias "$ALIAS" --ks-pass env:SAFI_KEY_PASS --key-pass env:SAFI_KEY_PASS \
 --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true --out "$WORK/probe.apk" "$WORK/probe-aligned.apk"
"$BT/apksigner" verify --print-certs "$WORK/probe.apk" | head -3
echo "Built QA-only APK: $WORK/probe.apk"
