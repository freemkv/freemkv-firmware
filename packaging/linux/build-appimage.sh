#!/usr/bin/env bash
# Build one tool's AppImage: the glibc eframe/egui desktop app plus its static
# CLI, mirroring freemkv's appimage.yml (linuxdeploy, pinned by the caller).
# eframe dlopens GL/EGL, X11/Wayland and xkbcommon from the host at run time,
# and linuxdeploy's excludelist keeps those out anyway, so unlike freemkv's GTK
# AppImage there is no toolkit to bundle -- just the two binaries.
#
# Run from the repository root:
#   LINUXDEPLOY=/path/to/linuxdeploy-<arch>.AppImage \
#     packaging/linux/build-appimage.sh <tool> <gui-binary> <cli-binary> <x86_64|aarch64> <out-dir>
# Produces <out-dir>/<tool>-<arch>-linux.AppImage and its .sha256. See AppRun.in
# for how the AppImage picks the GUI or the CLI.
set -euo pipefail

tool="$1" gui="$2" cli="$3" arch="$4" out="$5"
linuxdeploy="$(readlink -f "${LINUXDEPLOY:?set LINUXDEPLOY to the linuxdeploy AppImage}")"
id="org.freemkv.$tool-gui"
name="$tool-$arch-linux.AppImage"

work="$(mktemp -d)"
app="$work/AppDir"
icons="$app/usr/share/icons/hicolor/256x256/apps"
install -d -m 755 "$app/usr/bin" "$app/usr/libexec" "$app/usr/share/applications" "$icons" "$out"
install -m 755 "$gui" "$app/usr/bin/$tool-gui"
# The static CLI goes in usr/libexec, which linuxdeploy does not scan: it has
# no dependencies to bundle, and linuxdeploy's ldd/patchelf pass is only meant
# for dynamically linked executables in usr/bin.
install -m 755 "$cli" "$app/usr/libexec/$tool"
install -m 644 "packaging/linux/$id.desktop" "$app/usr/share/applications/$id.desktop"
convert "crates/$tool-gui/assets/freemkv.png" -resize 256x256 "$icons/$id.png"
sed "s/@TOOL@/$tool/g" packaging/linux/AppRun.in > "$work/AppRun"
chmod 755 "$work/AppRun"

(
  cd "$work"
  APPIMAGE_EXTRACT_AND_RUN=1 ARCH="$arch" LDAI_OUTPUT="$name" OUTPUT="$name" \
    "$linuxdeploy" --appdir AppDir \
      --executable "AppDir/usr/bin/$tool-gui" \
      --desktop-file "AppDir/usr/share/applications/$id.desktop" \
      --icon-file "AppDir/usr/share/icons/hicolor/256x256/apps/$id.png" \
      --custom-apprun AppRun \
      --output appimage
)
# Take whatever single AppImage linuxdeploy wrote, whichever output-name
# variable its appimage plugin honoured.
shopt -s nullglob
built=("$work"/*.AppImage)
[ "${#built[@]}" -eq 1 ] || { echo "expected one AppImage, got: ${built[*]:-none}" >&2; exit 1; }
mv "${built[0]}" "$out/$name"
chmod 755 "$out/$name"
(cd "$out" && sha256sum "$name" > "$name.sha256")
rm -rf "$work"
ls -l "$out/$name"
