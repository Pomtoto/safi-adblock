# Safi 1.1.0 validation scope

This update adds optional HaGeZi NORMAL filtering and an opt-in, RAM-only DNS diagnostic recorder. LIGHT stays the default. It does **not** establish that the ad reported in Passion Drama Lite is fixed.

## Added deterministic checks

`tools/test-core.sh` now runs the original 64 assertions / 4,000 malformed-packet fuzz cases plus `DiagnosticTests` (31 additional assertions):

- Disabled by default: no stored names before consent.
- Two-minute capture window and bounded 128-row storage.
- New session invalidates prior request tickets and discards old data.
- Stop, explicit clear and 15-minute retention expiry.
- Reject URLs, control characters and invalid status codes.
- Immutable snapshots, concurrent counting, report-scope warnings.
- Resolver integration: blocked, allowed, cached and failed outcomes.
- Profile allowlist precedence, stable LIGHT default, fixed upstream URLs, and real bundled counts for LIGHT and NORMAL.

Local JVM tests passed before publication. The actual GitHub build, lint and signature result is in the linked run/release rather than assumed from local tests.

## Runtime limitations

The existing Android 9 emulator validation in `TESTING.md` pertains to the original 1.0 APK, not a new physical-device or Passion Drama Lite test of 1.1.0. New dialogs, clipboard behavior and profile switching need user/device validation. GitHub CI does not launch a phone/emulator in this workflow.

No systemless/root mode, TLS interception, first-party drama-domain blacklist, purchase bypass, or fabricated reward callbacks were added. No user screenshots or real diagnostic records are included in this repository.
