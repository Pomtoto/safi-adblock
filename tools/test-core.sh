#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
SRC="$ROOT/app/src/main/java/app/safi/shield"
javac -J-Xmx192m -encoding UTF-8 --release 8 -d "$WORK" \
 "$SRC/DomainRules.java" "$SRC/DnsCodec.java" "$SRC/IpPacket.java" "$SRC/TcpDnsProxy.java" \
 "$SRC/DohResolver.java" "$SRC/DnsProvider.java" "$SRC/ListSource.java" \
 "$SRC/DiagnosticRecorder.java" "$SRC/BlockProfile.java" \
 "$ROOT/tests/CoreTests.java" "$ROOT/tests/DiagnosticTests.java" "$ROOT/tests/HardeningTests.java"
java -Xmx160m -cp "$WORK" app.safi.shield.CoreTests "$ROOT/app/src/main/assets/hagezi-light.txt" "$@"
java -Xmx192m -cp "$WORK" app.safi.shield.DiagnosticTests \
 "$ROOT/app/src/main/assets/hagezi-light.txt" "$ROOT/app/src/main/assets/hagezi-normal.txt"
java -Xmx192m -cp "$WORK" app.safi.shield.HardeningTests "$ROOT/app/src/main/assets/hagezi-light.txt" "$@"
