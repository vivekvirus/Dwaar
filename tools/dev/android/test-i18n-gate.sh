#!/usr/bin/env bash
# Proves the Gradle i18n gate fails the build when a guard.* key is missing in a supported language (INV-11, UX-08).
# Works on a TEMP COPY of packages/i18n; the real catalogs are never modified.
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/root/android-sdk}}"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
cp -r "$repo/packages/i18n/locales" "$repo/packages/i18n/audio" "$repo/packages/i18n/icons.yaml" "$tmp/"
python3 - "$tmp" <<'PY'
import json, sys
p = f"{sys.argv[1]}/locales/mr/guard.json"
d = json.load(open(p, encoding="utf-8")); d.pop("tile.guest"); json.dump(d, open(p, "w", encoding="utf-8"), ensure_ascii=False)
PY
cd "$repo/apps/guard-android"
if flock /tmp/dwaar-gradle.lock ./gradlew :core:verifyI18nCatalogs -Pdwaar.i18nRoot="$tmp" --console=plain >"$tmp/out.txt" 2>&1; then
  echo "FAIL: the gate passed although mr/guard.json lacks tile.guest"; exit 1
fi
grep -q "mr/guard.json is missing key 'tile.guest'" "$tmp/out.txt" && echo "OK: build failed as required (mr/guard.json is missing key 'tile.guest')" \
  || { echo "FAIL: build failed for another reason"; tail -30 "$tmp/out.txt"; exit 1; }
