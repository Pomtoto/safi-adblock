#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Dependency-free build: official SDK 35 + Build Tools 35.0.0, Java 11+.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
: "${SDK:?Set ANDROID_SDK_ROOT to an SDK with platform 35 and build-tools 35.0.0}"
BT="$SDK/build-tools/${ANDROID_BUILD_TOOLS:-35.0.0}"
JAR="$SDK/platforms/android-35/android.jar"
WORK="$ROOT/artifacts"
rm -rf "$WORK/classes" "$WORK/generated" "$WORK/dex"
mkdir -p "$WORK"/{classes,generated,dex}
python3 - "$ROOT/app/src/main/AndroidManifest.xml" "$WORK/AndroidManifest.xml" <<'PY'
import sys,xml.etree.ElementTree as E
E.register_namespace('android','http://schemas.android.com/apk/res/android')
t=E.parse(sys.argv[1]);t.getroot().set('package','app.safi.shield');t.write(sys.argv[2],encoding='utf-8',xml_declaration=True)
PY
"$BT/aapt2" compile --dir "$ROOT/app/src/main/res" -o "$WORK/resources.zip"
"$BT/aapt2" link -o "$WORK/resources.apk" --manifest "$WORK/AndroidManifest.xml" -I "$JAR" \
 --java "$WORK/generated" --min-sdk-version 26 --target-sdk-version 35 --version-code 1 --version-name 1.0.0 \
 -A "$ROOT/app/src/main/assets" "$WORK/resources.zip"
find "$ROOT/app/src/main/java" "$WORK/generated" -name '*.java' > "$WORK/sources.txt"
javac -J-Xmx256m -encoding UTF-8 --release 8 -classpath "$JAR" -d "$WORK/classes" @"$WORK/sources.txt"
jar cf "$WORK/classes.jar" -C "$WORK/classes" .
java -Xmx256m -cp "$BT/lib/d8.jar" com.android.tools.r8.D8 --min-api 26 --lib "$JAR" --output "$WORK/dex" "$WORK/classes.jar"
cp "$WORK/resources.apk" "$WORK/unsigned.apk"
(cd "$WORK/dex" && zip -q "$WORK/unsigned.apk" classes.dex)
"$BT/zipalign" -f -p 4 "$WORK/unsigned.apk" "$WORK/aligned.apk"
KEY="${SAFI_KEYSTORE:-$HOME/.cache/safi-signing.jks}"
export SAFI_KEY_PASS="${SAFI_KEY_PASS:-android}"
ALIAS="${SAFI_KEY_ALIAS:-safi}"
if [[ ! -f "$KEY" ]]; then
 mkdir -p "$(dirname "$KEY")"
 keytool -genkeypair -keystore "$KEY" -storepass:env SAFI_KEY_PASS -keypass:env SAFI_KEY_PASS -alias "$ALIAS" \
  -keyalg RSA -keysize 3072 -validity 10000 -dname 'CN=Safi Local Build, O=Safi, C=IQ' -noprompt
fi
"$BT/apksigner" sign --ks "$KEY" --ks-key-alias "$ALIAS" --ks-pass env:SAFI_KEY_PASS --key-pass env:SAFI_KEY_PASS \
 --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true --v4-signing-enabled false \
 --out "$WORK/Safi-1.0.apk" "$WORK/aligned.apk"
"$BT/apksigner" verify --verbose --print-certs "$WORK/Safi-1.0.apk"
"$BT/zipalign" -c -v 4 "$WORK/Safi-1.0.apk" | tail -1
sha256sum "$WORK/Safi-1.0.apk"
echo "Built: $WORK/Safi-1.0.apk"
