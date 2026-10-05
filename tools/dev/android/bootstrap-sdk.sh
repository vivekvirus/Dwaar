#!/usr/bin/env bash
# Reproduce the Android SDK used by apps/guard-android on a clean machine.
# SDK location: ANDROID_HOME or ANDROID_SDK_ROOT if set; otherwise /root/android-sdk (this script only;
# the Gradle build itself never reads a default path and needs no local.properties).
# Needs: java (17+), curl, unzip. TLS verification is never disabled; behind a proxy set
# HTTPS_PROXY and a trusted CA bundle (SSL_CERT_FILE / JAVA_TOOL_OPTIONS) as usual.
set -euo pipefail

CMDLINE_TOOLS_ZIP="commandlinetools-linux-11076708_latest.zip"   # cmdline-tools 12.0
CMDLINE_TOOLS_URL="https://dl.google.com/android/repository/${CMDLINE_TOOLS_ZIP}"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/root/android-sdk}}"
PACKAGES=("platform-tools" "platforms;android-35" "build-tools;35.0.0")

mkdir -p "$SDK/cmdline-tools"
if [ ! -x "$SDK/cmdline-tools/latest/bin/sdkmanager" ]; then
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  curl -fsSL --retry 3 -o "$tmp/$CMDLINE_TOOLS_ZIP" "$CMDLINE_TOOLS_URL"
  unzip -q "$tmp/$CMDLINE_TOOLS_ZIP" -d "$tmp"
  rm -rf "$SDK/cmdline-tools/latest"
  mv "$tmp/cmdline-tools" "$SDK/cmdline-tools/latest"
fi

SDKMANAGER="$SDK/cmdline-tools/latest/bin/sdkmanager"
# Accepting licences is an explicit legal step: it is done here on purpose, once, for the packages above.
yes | "$SDKMANAGER" --sdk_root="$SDK" --licenses >/dev/null || true
"$SDKMANAGER" --sdk_root="$SDK" "${PACKAGES[@]}"

echo "Android SDK ready at $SDK"
echo "export ANDROID_HOME=$SDK"
