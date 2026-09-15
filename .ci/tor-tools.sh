#!/usr/bin/env bash
# Isolated test tools only. No daemon, system package, or host configuration.
set -euo pipefail
test -n "$TOOL_ROOT"
test -n "$ARTIFACT_ROOT"
test -d "$OPENSSL_INCLUDE_DIR/openssl"
test -d "$LIBEVENT_INCLUDE_DIR/event2"
test -f "$ZLIB_INCLUDE_DIR/zlib.h"
test -x "$UV_BIN"
test -x "$MAKE_BIN"
export MAKE="$MAKE_BIN"
artifact_dir="$ARTIFACT_ROOT/$CI_COMMIT_SHA/tor-tools"
mkdir -p "$TOOL_ROOT" "$artifact_dir"
scratch="$(mktemp -d "$TOOL_ROOT/.build-XXXXXXXX")"
cleanup() {
  if test -f "$scratch/tor-0.4.9.12/config.log"; then
    cp "$scratch/tor-0.4.9.12/config.log" "$artifact_dir/tor-config.log"
  fi
  rm -rf -- "$scratch"
}
trap cleanup EXIT
version=0.4.9.12
source_hash=c0d307c9dcdaee4848a8ca53e9d6c4ec92823e4f30be12790b0fbddfc6515f5b
curl --fail --silent --show-error --location --max-time 180 \
  "https://dist.torproject.org/tor-$version.tar.gz" --output "$scratch/tor.tar.gz"
printf '%s  %s\n' "$source_hash" "$scratch/tor.tar.gz" | sha256sum --check --strict
tar --extract --gzip --file "$scratch/tor.tar.gz" --directory "$scratch" --no-same-owner
export CPPFLAGS="-I$OPENSSL_INCLUDE_DIR -I$LIBEVENT_INCLUDE_DIR -I$ZLIB_INCLUDE_DIR"
export LDFLAGS="-L$OPENSSL_LIB_DIR -L$LIBEVENT_LIB_DIR -L$ZLIB_LIB_DIR -Wl,-rpath,$OPENSSL_LIB_DIR -Wl,-rpath,$LIBEVENT_LIB_DIR -Wl,-rpath,$ZLIB_LIB_DIR"
export LD_LIBRARY_PATH="$OPENSSL_LIB_DIR:$LIBEVENT_LIB_DIR:$ZLIB_LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
tor_prefix="$TOOL_ROOT/tor-$version-$CI_COMMIT_SHA"
test ! -e "$tor_prefix"
(
  cd "$scratch/tor-$version"
  timeout 180 ./configure --prefix="$tor_prefix" --disable-dependency-tracking --disable-asciidoc --disable-unittests \
    --disable-manpage --disable-html-manual --disable-lzma --disable-zstd \
    --disable-system-torrc
  timeout 1200 "$MAKE_BIN" -j2
  timeout 120 "$MAKE_BIN" install
) 2>&1 | tee "$artifact_dir/tor-build.log"
"$tor_prefix/bin/tor" --version > "$artifact_dir/tor-version.txt"
test -x "$tor_prefix/bin/tor-gencert"
printf '%s  %s\n' "$CHUTNEY_SOURCE_SHA256" "$CHUTNEY_SOURCE_ARCHIVE" | sha256sum --check --strict
test "$(git get-tar-commit-id < "$CHUTNEY_SOURCE_ARCHIVE")" = 6cc158868d722e652975cb4efd5b278d95ff2fbb
chutney_prefix="$TOOL_ROOT/chutney-$CI_COMMIT_SHA"
test ! -e "$chutney_prefix"
mkdir "$chutney_prefix"
tar --extract --file "$CHUTNEY_SOURCE_ARCHIVE" --directory "$chutney_prefix" --no-same-owner
export UV_CACHE_DIR="$TOOL_ROOT/uv-cache"
export UV_PYTHON_DOWNLOADS=never
venv="$TOOL_ROOT/python-$CI_COMMIT_SHA"
test ! -e "$venv"
"$UV_BIN" venv --python "$(command -v python3)" "$venv"
"$UV_BIN" pip compile "$chutney_prefix/pyproject.toml" --python "$venv/bin/python" \
  --generate-hashes --output-file "$artifact_dir/chutney-requirements.txt"
"$UV_BIN" pip sync --python "$venv/bin/python" --require-hashes "$artifact_dir/chutney-requirements.txt"
"$venv/bin/python" --version > "$artifact_dir/python-version.txt"
python3 - "$artifact_dir/tools.json" "$tor_prefix" "$venv" "$chutney_prefix" "$source_hash" "$CHUTNEY_SOURCE_SHA256" <<'PY'
import json,pathlib,sys
output,tor,venv,chutney,tor_hash,chutney_hash=sys.argv[1:]
pathlib.Path(output).write_text(json.dumps({
    "torBin":tor+"/bin/tor", "torGencert":tor+"/bin/tor-gencert",
    "python":venv+"/bin/python", "chutney":chutney,
    "torSourceSha256":tor_hash, "chutneySourceSha256":chutney_hash,
    "scope":"isolated synthetic CI tools; no running service"
},indent=2)+"\n")
PY
(
  cd "$artifact_dir"
  sha256sum tor-build.log tor-version.txt python-version.txt tools.json chutney-requirements.txt > SHA256SUMS
)
