#!/bin/zsh
set -euo pipefail
ROOT="${0:A:h}"
APP="$ROOT/dist/Agent B.app"

# --- Signing ---------------------------------------------------------------
# Set SIGN_IDENTITY to your "Developer ID Application: … (TEAMID)" identity to
# produce a distributable, notarizable build. Leave it unset for a local
# ad-hoc signature (works on this Mac only; Gatekeeper will warn elsewhere).
#   security find-identity -v -p codesigning   # lists installed identities
SIGN_IDENTITY="${SIGN_IDENTITY:--}"

# Optional notarization: create a stored credential once with
#   xcrun notarytool store-credentials <profile> --apple-id … --team-id … --password …
# then run this script with NOTARIZE_KEYCHAIN_PROFILE=<profile>.
NOTARIZE_KEYCHAIN_PROFILE="${NOTARIZE_KEYCHAIN_PROFILE:-}"

# --- Optional model credential --------------------------------------------
# The app treats a bundled model-auth.json as optional (AgentB.m only uses it
# when present); otherwise the model key is configured in Settings at runtime.
# Point MODEL_AUTH_FILE at an auth.json to bake one in.
MODEL_AUTH_FILE="${MODEL_AUTH_FILE:-}"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/harness"

# Pin the SDK to the active Xcode toolchain so clang cannot fall back to a
# mismatched CommandLineTools stub SDK (which triggers "unknown architecture"
# link errors). Override by exporting SDKROOT yourself.
export SDKROOT="${SDKROOT:-$(xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)}"

CLANG_MODULE_CACHE_PATH="${TMPDIR:-/tmp}/agent-b-clang-cache" xcrun clang -O2 -fobjc-arc -fmodules \
  -mmacosx-version-min=13.0 -framework Cocoa -framework WebKit \
  "$ROOT/macos/AgentB.m" -o "$APP/Contents/MacOS/Agent B"

cp "$ROOT/macos/Info.plist" "$APP/Contents/Info.plist"
cp "$ROOT/macos/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
cp -R "$ROOT/agent_b_harness" "$APP/Contents/Resources/harness/"
cp -R "$ROOT/static" "$APP/Contents/Resources/harness/"

if [[ -n "$MODEL_AUTH_FILE" && -f "$MODEL_AUTH_FILE" ]]; then
  cp "$MODEL_AUTH_FILE" "$APP/Contents/Resources/model-auth.json"
  chmod 600 "$APP/Contents/Resources/model-auth.json"
  echo "Embedded model auth from: $MODEL_AUTH_FILE"
else
  echo "No model auth embedded (set MODEL_AUTH_FILE=/path/to/auth.json to bake one in; otherwise configure the key in Settings)."
fi

find "$APP" -name __pycache__ -type d -prune -exec rm -rf {} +

if [[ "$SIGN_IDENTITY" == "-" ]]; then
  codesign --force --deep --sign - "$APP"
  echo "Ad-hoc signed (local use only). Set SIGN_IDENTITY to your Developer ID for distribution."
else
  codesign --force --deep --options runtime --timestamp --sign "$SIGN_IDENTITY" "$APP"
  echo "Signed with: $SIGN_IDENTITY"
  if [[ -n "$NOTARIZE_KEYCHAIN_PROFILE" ]]; then
    ZIP="${TMPDIR:-/tmp}/AgentB-notarize.zip"
    /usr/bin/ditto -c -k --keepParent "$APP" "$ZIP"
    xcrun notarytool submit "$ZIP" --keychain-profile "$NOTARIZE_KEYCHAIN_PROFILE" --wait
    xcrun stapler staple "$APP"
    rm -f "$ZIP"
    echo "Notarized and stapled."
  else
    echo "Skipping notarization (set NOTARIZE_KEYCHAIN_PROFILE to notarize)."
  fi
fi

echo "Built: $APP"
