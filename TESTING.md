# Validation record — Safi 1.0.0

This record describes the original direct-SDK APK identified below. Later GitHub CI builds have their own run reports and BUILD-INFO.txt; see [CI.md](CI.md).

Date: 2026-09-07. This is an experimental, sideloadable build, not a production certification or guarantee for every Android device or ad network.

## Built APK

- Application ID: `app.safi.shield`
- Minimum API: 26 (Android 8.0)
- Target/compile API: 35 (Android 15)
- No native libraries: architecture-independent Java/Dex APK.
- Built with official SDK Platform 35 and Build Tools 35.0.0: AAPT2 → javac (Java 8 bytecode) → D8 → zipalign → apksigner.
- Verified APK v2/v3 signatures and ZIP alignment. See `tests/apk-verification.txt`.
- APK SHA-256: `40be9b2c754feeb3f638cbfcbcf2fa158b8dee22915ba033ed18d6f2deb65f9c`
- Signing certificate SHA-256: `64d348b08d017ea23d9f54b667b7ca4938d93ab7080d19d74b7c75d60a114c99`

## JVM tests — passed

`tools/test-core.sh`: **64 assertions** and **4,000 malformed DNS/IP fuzz inputs**.

Coverage includes suffix boundaries; parent vs child rules; allowlist priority; IDN input; invalid user input; NXDOMAIN; query ID preservation; compressed CNAME parsing; malformed/compression-loop rejection; response/question matching; cache TTL and ID changes; UDP EDNS limits and truncation; IP, UDP and TCP checksums; TCP handshake, split framing, duplicate suppression, client sequence wrap, flow control and FIN cleanup; actual bundled list loading and a known blocked ad endpoint.

`tools/test-core.sh --live`: **65 assertions**, including a successful DNS wire-format POST to Cloudflare for `example.com`. The old Java 11 installation's CA store was updated for this test by pointing the host JVM at the current Debian system Java CA store. Certificate and hostname verification were not disabled. No testing CA, permissive trust manager or certificate override was added to the application.

Results: `tests/core-test-results.txt`, `tests/live-doh-results.txt`.

## Android runtime — passed on API 28

Installed the signed APK on a **32-bit x86 AOSP Android 9 / API 28 emulator**, running in software emulation. Opened the real native Arabic UI and accepted the standard Android VPN consent dialog. The application did not request or use `su`, root access, host-file changes or a user-installed CA.

A **separate application/UID**, built from `tests/device/ProbeActivity.java`, acted as a real client of the VPN:

| Check | Result |
|---|---|
| UDP A request to an ad endpoint returns NXDOMAIN | PASS |
| UDP AAAA request to an ad endpoint returns NXDOMAIN | PASS |
| Allowed UDP lookup receives a real DoH answer | PASS |
| TCP ad lookup returns NXDOMAIN | PASS |
| Allowed TCP lookup returns an answer | PASS |
| TCP DNSKEY query to `org` (593-byte DNS answer) | PASS |
| Android system resolver blocks the ad endpoint | PASS |
| Android system resolver resolves an ordinary domain | PASS |

The initial probe was launched immediately after accepting VPN consent, before the slow emulator had finished establishing the interface; its first UDP request timed out. After confirming the active route/interface, the complete suite was rerun and **all 8 checks passed**. Both runs are retained in `tests/device-test-results.txt` rather than hiding the initial timing failure. When reproducing, wait for **الحماية تعمل** before running the probe.

The emulator initially showed a System UI ANR under resource pressure during first boot. It was dismissed before validation. This was not a Safi application crash. Android runtime testing on this constrained emulator does not establish production performance, battery usage, or reliability under memory pressure.

### Stop / restore check

Tapped the actual in-app Stop button:

- Foreground VPN service disappeared.
- Virtual DNS route was removed.
- A separate-UID probe resolved the ad endpoint normally after stopping: **1 additional test passed**.

Evidence: `tests/device-vpn-route.txt`, `tests/device-service.txt`, `tests/device-after-stop.txt`, `tests/device-test-results.txt`.

Actual native screenshots are in `tests/screenshots/`; the counters shown come from the device test queries, not fabricated advertising statistics.

## Reproduce device checks

```bash
export ANDROID_SDK_ROOT=/path/to/android-sdk
bash tools/build-apk.sh
bash tools/build-device-probe.sh
adb install -r artifacts/Safi-1.0.apk
adb install -r artifacts/probe/probe.apk
adb shell am start -n app.safi.shield/.MainActivity
# Manually read the disclosure, allow the VPN, and wait for الحماية تعمل.
adb shell am start -n app.safi.probe/.ProbeActivity
adb logcat -s SafiProbe:I
# Stop Safi from its actual UI before the following check:
adb shell am force-stop app.safi.probe
adb shell am start -n app.safi.probe/.ProbeActivity --ez bypass true
```

The probe APK is a QA tool only; it is not included in the distributed Safi application.

## Not validated / limitations

- No physical handset was available. Runtime validation is limited to the API 28 emulator, not the user's device, Android 14/15/16 foreground-service behavior, OEM battery savers, or all supported OS versions.
- A newer API 35 emulator exceeded this workspace's RAM budget, so API 35 was compile-checked but not runtime-tested.
- Gradle/Android Studio project files are included; the delivered APK was built with the documented direct SDK path, not a completed Gradle build.
- Per-application exclusions, list updates, radio handover, long-duration load, every TCP edge case, and adversarial protocol testing beyond the included checks were not exhaustively tested on-device.
- The blocklist is a dated snapshot. Same-origin advertising, application-owned encrypted DNS, direct IP connections, DNS caches and already-downloaded ads can bypass DNS-level filtering.
- Stay in the app until a list update completes. If the Activity is closed or recreated during an update, stop/start protection afterward to ensure the new on-disk list is loaded.

**بالعربي:** نجح البناء والتثبيت والفحص على محاكي أندرويد 9، لكن النسخة تجريبية وليست مضمونة على كل هاتف. إذا تأثر الإنترنت أو تطبيق معيّن، أوقف الحماية أو استثنِ التطبيق. لا تتوقع إزالة جميع إعلانات يوتيوب أو تطبيقات التواصل.
