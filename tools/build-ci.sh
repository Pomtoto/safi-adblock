#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Signs the Gradle release APK inside GitHub Actions. No secret is committed or archived.
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
: "${SDK:?Android SDK is required}"
: "${ANDROID_SIGNING_KEYSTORE_B64:?Configure the encrypted repository signing secret}"
: "${ANDROID_SIGNING_PASSWORD:?Configure the encrypted repository password secret}"
: "${EXPECTED_CERT_SHA256:?Expected public signing-certificate fingerprint is required}"
ALIAS="${ANDROID_SIGNING_ALIAS:-safi}"
BT="$SDK/build-tools/${ANDROID_BUILD_TOOLS:-35.0.0}"
UNSIGNED="$ROOT/app/build/outputs/apk/release/app-release-unsigned.apk"
test -s "$UNSIGNED"
TEMP="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/safi-signing.XXXXXX")"
trap 'rm -rf "$TEMP"' EXIT
KEYSTORE="$TEMP/signing.p12"
printf '%s' "$ANDROID_SIGNING_KEYSTORE_B64" | base64 --decode > "$KEYSTORE"

# Validate public certificate before signing, to avoid accidentally breaking app upgrades.
keytool -exportcert -keystore "$KEYSTORE" -alias "$ALIAS" \
    -storepass:env ANDROID_SIGNING_PASSWORD > "$TEMP/certificate.der"
ACTUAL_CERT="$(sha256sum "$TEMP/certificate.der" | cut -d ' ' -f 1)"
if [[ "$ACTUAL_CERT" != "$EXPECTED_CERT_SHA256" ]]; then
    echo 'Signing certificate does not match the existing application. Stopping.' >&2
    exit 1
fi

VERSION="$("$BT/aapt2" dump badging "$UNSIGNED" | sed -n "s/.*versionName='\([^']*\)'.*/\1/p" | head -n 1)"
if [[ ! "$VERSION" =~ ^[a-zA-Z0-9._-]+$ ]]; then
    echo 'Invalid or missing APK version name.' >&2
    exit 1
fi
OUTPUT="$ROOT/release-output"
mkdir -p "$OUTPUT"
APK="$OUTPUT/Safi-$VERSION-github.apk"
"$BT/zipalign" -f -p 4 "$UNSIGNED" "$TEMP/aligned.apk"
"$BT/apksigner" sign --ks "$KEYSTORE" --ks-key-alias "$ALIAS" \
    --ks-pass env:ANDROID_SIGNING_PASSWORD --key-pass env:ANDROID_SIGNING_PASSWORD \
    --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true --v4-signing-enabled false \
    --out "$APK" "$TEMP/aligned.apk"
"$BT/apksigner" verify --verbose --print-certs "$APK" | tee "$OUTPUT/APK-VERIFICATION.txt"
"$BT/zipalign" -c 4 "$APK"
(cd "$OUTPUT" && sha256sum ./*.apk > SHA256SUMS.txt)
{
    printf 'Safi version: %s\n' "$VERSION"
    printf 'Source commit: %s\n' "${GITHUB_SHA:-local}"
    printf 'Build URL: %s/%s/actions/runs/%s\n' "${GITHUB_SERVER_URL:-https://github.com}" "${GITHUB_REPOSITORY:-local}" "${GITHUB_RUN_ID:-local}"
    printf 'Android compile/target API: 35\nMinimum Android API: 26\n'
    printf 'Android build tools: %s\n' "${ANDROID_BUILD_TOOLS:-35.0.0}"
    printf 'Public signing certificate SHA-256: %s\n' "$ACTUAL_CERT"
    printf 'Built with Gradle; original application signing identity preserved.\n'
    printf 'CI build/test success is not a physical-device test or universal ad-blocking guarantee.\n'
} > "$OUTPUT/BUILD-INFO.txt"
echo "Signed APK ready: $(basename "$APK")"
