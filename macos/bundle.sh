#!/bin/bash
# Assemble a <gui-bin>.app from a built GUI binary.
#
#   bundle.sh <gui-bin>                       local build, debug, current arch
#   bundle.sh <gui-bin> release               local build, release, current arch
#   bundle.sh <gui-bin> release <rust-target> a specific cross-built target
#
# firmware ships TWO desktop apps, so this is parameterized by the GUI binary
# name (also the crate name: freemkv-flash-gui, freemkv-fw-gui). The release
# workflow calls it once per app per macOS architecture. The icon and the
# Info.plist are looked up from the binary name, so adding a third GUI needs no
# change here — only its own macos/<bin>.plist and crate assets/freemkv.icns.
#
# Ad-hoc signed only: firmware has no Developer ID secrets, so there is no
# notarization. The Homebrew casks strip com.apple.quarantine on install,
# exactly as the sibling freemkv-app cask does.
set -e
cd "$(dirname "$0")/.."

BIN_NAME=${1:?usage: bundle.sh <gui-bin> [release] [rust-target]}
PROFILE=${2:-debug}
TARGET=${3:-}

PLIST="macos/$BIN_NAME.plist"
ICNS="crates/$BIN_NAME/assets/freemkv.icns"
[ -f "$PLIST" ] || { echo "missing $PLIST" >&2; exit 1; }
[ -f "$ICNS" ] || { echo "missing $ICNS" >&2; exit 1; }

APP="target/$BIN_NAME.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

cp "$PLIST" "$APP/Contents/Info.plist"
cp "$ICNS" "$APP/Contents/Resources/freemkv.icns"

# Build first so the bundle can never ship a stale binary.
BUILD=(cargo build -p "$BIN_NAME")
[ "$PROFILE" = release ] && BUILD+=(--release)
[ -n "$TARGET" ] && BUILD+=(--target "$TARGET")
"${BUILD[@]}"

if [ -n "$TARGET" ]; then
  BIN="target/$TARGET/$PROFILE/$BIN_NAME"
else
  BIN="target/$PROFILE/$BIN_NAME"
fi
[ -f "$BIN" ] || { echo "missing $BIN — build failed?" >&2; exit 1; }
cp "$BIN" "$APP/Contents/MacOS/$BIN_NAME"

# Ad-hoc signature. An unsigned arm64 bundle will not load at all (Gatekeeper
# reports "app is damaged"); the ad-hoc sign fixes that. It is NOT a
# distributable signature — that is what the cask's quarantine strip is for.
# Signed inner-out, no --deep (deprecated, and it re-signs nested code wrong).
codesign --force --sign - "$APP/Contents/MacOS/$BIN_NAME"
codesign --force --sign - "$APP"
echo "built $APP ($(lipo -archs "$APP/Contents/MacOS/$BIN_NAME")) — ad-hoc signed"
