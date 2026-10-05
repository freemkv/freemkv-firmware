#!/usr/bin/env bash
# Build the freemkv-firmware .deb packages for one architecture (Ubuntu 24.04
# baseline). Mirrors freemkv's packaging/deb/build.py: stable `<pkg>-<arch>.deb`
# names with a `.sha256` sidecar, dpkg-deb --root-owner-group, reproducible
# (SOURCE_DATE_EPOCH, gzip -n), README.Debian with the optical-drive note.
#   freemkv-flash, freemkv-fw           the static musl CLI only, no Depends
#                                       (like freemkv-cli)
#   freemkv-flash-gui, freemkv-fw-gui   the glibc eframe/egui desktop app AND the
#                                       same static CLI (like freemkv's app deb,
#                                       which carries its CLI too)
# Each GUI package and its CLI package both ship /usr/bin/<cli>, so they
# Conflict/Replace each other exactly as freemkv / freemkv-cli do: installing
# one swaps out the other.
#
# Run from the repository root, on a host of the package's architecture (the
# GUI runtime deps come from dpkg-shlibdeps):
#   packaging/linux/build-debs.sh <amd64|arm64|armhf> <cli-dir> <gui-dir|-> <out-dir>
# <cli-dir> holds the `build` job's bare static CLIs
# (freemkv-{flash,fw}-cli-<x86_64|aarch64|armv7>-linux); <gui-dir> holds the
# glibc freemkv-{flash,fw}-gui binaries, or is `-` to build the CLI packages only.
set -euo pipefail

arch="$1" cli_dir="$2" gui_dir="$3" out="$4"
case "$arch" in
  amd64) triple=x86_64 ;;
  arm64) triple=aarch64 ;;
  armhf) triple=armv7 ;;
  *) echo "unsupported architecture: $arch" >&2; exit 2 ;;
esac

ver="$(grep -m1 '^version = ' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"
epoch="$(git log -1 --format=%ct)"
maint='Matthew Jackson <1085847+MattJackson@users.noreply.github.com>'
mkdir -p "$out"

# Same wording as freemkv's packages: nothing here touches udev rules, device
# permissions or group memberships.
device_note="Optical drives use the distribution's existing device ACLs and group permissions.
Use an active local desktop session. If access is denied, inspect the device
owner/group and your distribution's optical-drive access policy. No device
permissions or group memberships are changed by this package."
flash_note="freemkv-flash info and dump only read from the drive. Writing firmware (flash)
sends commands such as WRITE BUFFER that the Linux kernel's SCSI command filter
only passes for privileged processes (CAP_SYS_RAWIO), so a flash normally has to
run as root, e.g.: sudo freemkv-flash flash ...
A flash can brick a drive given the wrong image; dump a backup first."
fw_note="freemkv-fw works on firmware image files only and never opens a drive. Pair it
with freemkv-flash to write a modified image."

# mkdeb <pkg> <cli-binary> <gui-binary|''> <depends> <recommends> <summary> <long description> <homepage-slug> <readme>
# <pkg> is the CLI name (freemkv-flash); with a GUI binary it builds <pkg>-gui.
mkdeb() {
  local cli="$1" clibin="$2" guibin="$3" depends="$4" recommends="$5" summary="$6" long="$7" slug="$8" readme="$9"
  local pkg="$cli" other="$cli-gui" root doc size
  if [ -n "$guibin" ]; then pkg="$cli-gui" other="$cli"; fi
  root="$(mktemp -d)"; doc="$root/usr/share/doc/$pkg"
  install -d -m 755 "$root/usr/bin" "$doc" "$root/usr/share/man/man1" "$root/DEBIAN" "$root/usr/share/lintian/overrides"
  # The static CLI ships as built (release profile already strips it; binutils
  # strip on an amd64 host cannot rewrite an arm64 binary anyway).
  install -m 755 "$clibin" "$root/usr/bin/$cli"
  printf '%s: statically-linked-binary [usr/bin/%s]\n' "$pkg" "$cli" > "$root/usr/share/lintian/overrides/$pkg"
  if [ -n "$guibin" ]; then
    install -m 755 "$guibin" "$root/usr/bin/$pkg"
    strip --strip-unneeded "$root/usr/bin/$pkg"
  fi
  { cat LICENSE; printf '\nUpstream: https://github.com/freemkv/freemkv-firmware\n'; } > "$doc/copyright"
  printf '%s\n' "$readme" > "$doc/README.Debian"
  printf '%s (%s) unstable; urgency=medium\n\n  * Package the upstream release for Ubuntu 24.04 %s.\n\n -- %s  %s\n' \
    "$pkg" "$ver" "$arch" "$maint" "$(date -u -R -d "@$epoch")" | gzip -9n > "$doc/changelog.Debian.gz"
  gzip -9n < CHANGELOG.md > "$doc/changelog.gz"
  printf '.TH %s 1\n.SH NAME\n%s \\- %s\n.SH SEE ALSO\nhttps://freemkv.org/firmware/%s/\n' \
    "$(echo "$pkg" | tr '[:lower:]' '[:upper:]')" "$pkg" "$summary" "$slug" | gzip -9n > "$root/usr/share/man/man1/$pkg.1.gz"
  if [ -n "$guibin" ]; then
    local icondir="$root/usr/share/icons/hicolor/256x256/apps"
    install -d -m 755 "$root/usr/share/applications" "$icondir"
    install -m 644 "packaging/linux/org.freemkv.$pkg.desktop" "$root/usr/share/applications/"
    convert "crates/$pkg/assets/freemkv.png" -resize 256x256 "$icondir/org.freemkv.$pkg.png"
    printf '.TH %s 1\n.SH NAME\n%s \\- %s\n.SH SEE ALSO\n%s(1), https://freemkv.org/firmware/%s/\n' \
      "$(echo "$cli" | tr '[:lower:]' '[:upper:]')" "$cli" "$summary (command line)" "$pkg" "$slug" \
      | gzip -9n > "$root/usr/share/man/man1/$cli.1.gz"
  fi
  find "$root" -type d -exec chmod 755 {} +
  find "$root" -type f ! -path "$root/usr/bin/*" -exec chmod 644 {} +
  size="$(du -sk --exclude=DEBIAN "$root" | cut -f1)"
  {
    printf 'Package: %s\nVersion: %s\nArchitecture: %s\nSection: utils\nPriority: optional\n' "$pkg" "$ver" "$arch"
    printf 'Maintainer: %s\nInstalled-Size: %s\n' "$maint" "$size"
    if [ -n "$depends" ]; then printf 'Depends: %s\n' "$depends"; fi
    if [ -n "$recommends" ]; then printf 'Recommends: %s\n' "$recommends"; fi
    printf 'Conflicts: %s\nReplaces: %s\n' "$other" "$other"
    printf 'Homepage: https://freemkv.org/firmware/%s/\nDescription: %s\n%s\n' "$slug" "$summary" "$long"
  } > "$root/DEBIAN/control"
  (cd "$root" && find . -type f ! -path './DEBIAN/*' -printf '%P\n' | sort | xargs md5sum) > "$root/DEBIAN/md5sums"
  SOURCE_DATE_EPOCH="$epoch" dpkg-deb --root-owner-group --build "$root" "$out/$pkg-$arch.deb"
  (cd "$out" && sha256sum "$pkg-$arch.deb" > "$pkg-$arch.deb.sha256")
  rm -rf "$root"
}

# GUI runtime deps: dpkg-shlibdeps for what is linked, plus the libraries
# eframe/winit/glow dlopen at run time (invisible to it): GL/EGL, X11 and
# Wayland, xkbcommon.
shlibs() {
  # Absolute: dpkg-shlibdeps runs from a scratch dir. Empty output is an error.
  local bin d deps; bin="$(realpath "$1")"; d="$(mktemp -d)"; mkdir "$d/debian"
  printf 'Source: x\n\nPackage: x\nArchitecture: %s\nDescription: x\n' "$arch" > "$d/debian/control"
  deps="$(cd "$d" && dpkg-shlibdeps -O "$bin" | sed -n 's/^shlibs:Depends=//p')"
  rm -rf "$d"
  [ -n "$deps" ] || { echo "::error::dpkg-shlibdeps found no dependencies for $1" >&2; exit 1; }
  printf '%s\n' "$deps"
}
dl='libgl1, libegl1, libxkbcommon0, libxkbcommon-x11-0, libwayland-client0, libwayland-egl1, libx11-6, libxcursor1, libxi6, libxrandr2'
rec='libvulkan1, xdg-desktop-portal'

for t in flash fw; do
  cli="$cli_dir/freemkv-$t-cli-$triple-linux"
  # The CLI must be the static binary the deb advertises as dependency-free.
  if readelf -lW "$cli" | grep -Eq '^\s*INTERP\b'; then echo "::error::$cli is not static"; exit 1; fi
done

mkdeb freemkv-flash "$cli_dir/freemkv-flash-cli-$triple-linux" '' '' '' \
  'freemkv drive firmware flasher and dumper (command line)' \
  ' Reads, backs up and flashes optical-drive firmware (MediaTek MT19xx and
 Renesas; Pioneer live writes gated). info and dump are read-only; flash
 writes and can brick a drive given the wrong image.' flash \
  "Static $arch command-line build with no library dependencies.
Run freemkv-flash --help for usage. Install freemkv-flash-gui instead for the
desktop app; it includes this command too.

$device_note

$flash_note"
mkdeb freemkv-fw "$cli_dir/freemkv-fw-cli-$triple-linux" '' '' '' \
  'freemkv drive firmware modifier (command line)' \
  ' Builds and verifies modified optical-drive firmware images offline
 (MediaTek MT19xx integrity tables). It does not touch a drive itself;
 pair it with freemkv-flash to write one.' modify \
  "Static $arch command-line build with no library dependencies.
Run freemkv-fw --help for usage. Install freemkv-fw-gui instead for the
desktop app; it includes this command too.

$fw_note"

if [ "$gui_dir" = - ]; then ls -l "$out"; exit 0; fi

gui="$gui_dir/freemkv-flash-gui"
deps="$(shlibs "$gui")"  # a plain assignment, so set -e stops on failure
mkdeb freemkv-flash "$cli_dir/freemkv-flash-cli-$triple-linux" "$gui" "$deps, $dl" "$rec" \
  'freemkv Flash desktop app' \
  ' Minimal desktop app for freemkv-flash: drive info, dump and flash. Also
 installs the freemkv-flash command-line tool.' flash \
  "Built for Ubuntu 24.04 $arch and compatible derivatives such as Linux Mint 22.
Launch freemkv Flash from the application menu, or run freemkv-flash-gui.
The freemkv-flash command-line tool is installed too; run freemkv-flash --help.

$device_note

$flash_note
The desktop app runs as your user; if a flash is refused for lack of
privilege, run the same flash with the freemkv-flash command under sudo."
gui="$gui_dir/freemkv-fw-gui"
deps="$(shlibs "$gui")"  # a plain assignment, so set -e stops on failure
mkdeb freemkv-fw "$cli_dir/freemkv-fw-cli-$triple-linux" "$gui" "$deps, $dl" "$rec" \
  'freemkv Modify desktop app' \
  ' Minimal desktop app for freemkv-fw: create, verify, sign and probe. Also
 installs the freemkv-fw command-line tool.' modify \
  "Built for Ubuntu 24.04 $arch and compatible derivatives such as Linux Mint 22.
Launch freemkv Modify from the application menu, or run freemkv-fw-gui.
The freemkv-fw command-line tool is installed too; run freemkv-fw --help.

$fw_note"

ls -l "$out"
