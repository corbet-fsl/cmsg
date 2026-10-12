#!/usr/bin/env bash
# Sourced by the browser package job: prepare the pinned TorJS and Arti sources the
# Tor service stage needs, and export TORJS_SOURCE, ARTI_SOURCE and TORJS_TARGET_DIR.
# Revisions are the ones ctrn's browser/upstream/manifest.json pins; clones are
# verified against them and are always fresh and isolated.
tor_root="$1"
torjs_revision=65bb21d536a405ba706689ca384fad2ee25e60a7
arti_revision=2be5b51e895a687d1e7fc3ce1c01896730bcb9d3
bindgen_version=0.2.122
mkdir -p "$tor_root"
git clone --quiet https://github.com/privacy-ethereum/tor-js.git "$tor_root/tor-js"
git -C "$tor_root/tor-js" checkout --quiet "$torjs_revision"
git clone --quiet https://github.com/voltrevo/arti.git "$tor_root/arti"
git -C "$tor_root/arti" checkout --quiet "$arti_revision"
[[ "$(git -C "$tor_root/tor-js" rev-parse HEAD)" == "$torjs_revision" ]]
[[ "$(git -C "$tor_root/arti" rev-parse HEAD)" == "$arti_revision" ]]
(cd "$tor_root/tor-js" && npm ci --ignore-scripts --no-audit --no-fund)
# TorJS needs the exact wasm-bindgen CLI of its own lock.
bindgen_dir="$tor_root/bindgen"
mkdir -p "$bindgen_dir"
archive="wasm-bindgen-${bindgen_version}-x86_64-unknown-linux-musl.tar.gz"
base="https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${bindgen_version}"
(
  cd "$bindgen_dir"
  curl --fail --silent --show-error --location --retry 3 --remote-name "$base/$archive"
  curl --fail --silent --show-error --location --retry 3 --remote-name "$base/$archive.sha256sum"
  checksum=$(cut -d ' ' -f1 "$archive.sha256sum")
  printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check --strict
  tar -xzf "$archive" --strip-components=1
)
export TORJS_BINDGEN="$bindgen_dir/wasm-bindgen"
export TORJS_SOURCE="$tor_root/tor-js" ARTI_SOURCE="$tor_root/arti"
export TORJS_TARGET_DIR="${TORJS_TARGET_DIR:-${CARGO_HOME:-/caches/cargo}/torjs-target}"
printf 'tor sources: tor-js %s arti %s bindgen %s\n' "$torjs_revision" "$arti_revision" "$("$TORJS_BINDGEN" --version)"
