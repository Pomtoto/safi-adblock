#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
SRC="$ROOT/app/src/main/java/app/safi/shield"
javac -J-Xmx160m -encoding UTF-8 --release 8 -d "$WORK" \
 "$SRC/DomainRules.java" "$SRC/DnsCodec.java" "$SRC/IpPacket.java" "$SRC/TcpDnsProxy.java" "$SRC/DohResolver.java" "$ROOT/tests/CoreTests.java"
java -Xmx96m -cp "$WORK" app.safi.shield.CoreTests "$ROOT/app/src/main/assets/hagezi-light.txt" "$@"
