#!/bin/zsh
set -euo pipefail
ROOT="${0:A:h}"
SIGN_IDENTITY="${SIGN_IDENTITY:--}"
NOTARIZE_KEYCHAIN_PROFILE="${NOTARIZE_KEYCHAIN_PROFILE:-}"

# Never distribute credentials, including in private/local builds.
if [[ -n "${MODEL_AUTH_FILE:-}" ]]; then
  echo "MODEL_AUTH_FILE is no longer supported. Configure credentials in Settings, never in the app bundle." >&2
  exit 1
fi
if [[ -n "$NOTARIZE_KEYCHAIN_PROFILE" && "$SIGN_IDENTITY" == "-" ]]; then
  echo "Notarization requires SIGN_IDENTITY (Developer ID Application)." >&2
  exit 1
fi

# Pinned python-build-standalone release. Native-architecture builds only.
# Digests are upstream GitHub release-asset SHA-256 values, not a mutable latest URL.
case "$(uname -m)" in
  arm64) TARGET="aarch64-apple-darwin"; SHA256="c2edb321cd32ec2b170df208db0446dccc4398db602ca27cf2079098fb1f7d9d" ;;
  x86_64) TARGET="x86_64-apple-darwin"; SHA256="7ea9761b9069c10b9a20531d568645849d604c59e9c7f11f6659f1e1790c968e" ;;
  *) echo "Unsupported build architecture" >&2; exit 1 ;;
esac
RUNTIME_URL="https://github.com/astral-sh/python-build-standalone/releases/download/20260924/cpython-3.12.14%2B20260924-${TARGET}-install_only_stripped.tar.gz"
mkdir -p "$ROOT/dist"
BUILD_DIR="$(mktemp -d "$ROOT/dist/.build.XXXXXX")"
trap 'rm -rf "$BUILD_DIR"' EXIT
APP="$BUILD_DIR/Agent B.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/harness"
ARCHIVE="$BUILD_DIR/python.tar.gz"
if [[ -n "${PYTHON_RUNTIME_ARCHIVE:-}" ]]; then
  cp "$PYTHON_RUNTIME_ARCHIVE" "$ARCHIVE"
else
  curl --fail --location --proto '=https' --tlsv1.2 "$RUNTIME_URL" -o "$ARCHIVE"
fi
ACTUAL_SHA256="$(shasum -a 256 "$ARCHIVE" | cut -d ' ' -f 1)"
if [[ "$ACTUAL_SHA256" != "$SHA256" ]]; then
  echo "Bundled Python checksum mismatch; build aborted." >&2
  exit 1
fi
tar -xzf "$ARCHIVE" -C "$APP/Contents/Resources"
cp "$ROOT/macos/Python-runtime.md" "$APP/Contents/Resources/"

export SDKROOT="${SDKROOT:-$(xcrun --sdk macosx --show-sdk-path)}"
CLANG_MODULE_CACHE_PATH="$BUILD_DIR/clang-cache" xcrun clang -O2 -fobjc-arc -fmodules \
  -mmacosx-version-min=13.0 -framework Cocoa -framework WebKit \
  "$ROOT/macos/AgentB.m" -o "$APP/Contents/MacOS/Agent B"
cp "$ROOT/macos/Info.plist" "$APP/Contents/Info.plist"
cp "$ROOT/macos/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
cp -R "$ROOT/agent_b_harness" "$APP/Contents/Resources/harness/"
cp -R "$ROOT/static" "$APP/Contents/Resources/harness/"
find "$APP" -name __pycache__ -type d -prune -exec rm -rf {} +

# Sign nested Mach-O code first. Do not rely on codesign --deep to sign a bundle.
SIGN_FLAGS=(--force --sign "$SIGN_IDENTITY")
if [[ "$SIGN_IDENTITY" != "-" ]]; then
  SIGN_FLAGS+=(--options runtime --timestamp)
fi
while IFS= read -r -d '' BINARY; do
  if [[ "$(/usr/bin/file -b "$BINARY")" == Mach-O* ]]; then
    codesign "${SIGN_FLAGS[@]}" "$BINARY"
  fi
done < <(find "$APP/Contents/Resources/python" -type f -print0)
codesign "${SIGN_FLAGS[@]}" "$APP"
codesign --verify --deep --strict "$APP"

if [[ -n "$NOTARIZE_KEYCHAIN_PROFILE" ]]; then
  ZIP="$BUILD_DIR/notarize.zip"
  /usr/bin/ditto -c -k --keepParent "$APP" "$ZIP"
  xcrun notarytool submit "$ZIP" --keychain-profile "$NOTARIZE_KEYCHAIN_PROFILE" --wait
  xcrun stapler staple "$APP"
  xcrun stapler validate "$APP"
  spctl --assess --type execute --verbose=2 "$APP"
else
  echo "NOT NOTARIZED: development/beta build only. Set NOTARIZE_KEYCHAIN_PROFILE for public distribution."
fi

# Keep the last successful output recoverable until the maintainer removes it.
if [[ -e "$ROOT/dist/Agent B.app" ]]; then
  BACKUP_DIR="$(mktemp -d "$ROOT/dist/previous-build.XXXXXX")"
  mv "$ROOT/dist/Agent B.app" "$BACKUP_DIR/Agent B.app"
  echo "Previous build retained: $BACKUP_DIR"
fi
mv "$APP" "$ROOT/dist/Agent B.app"
echo "Built: $ROOT/dist/Agent B.app"
