#!/usr/bin/env bash
# Sourced: put the worker's lld and a wasm-capable clang in the environment.
# The wasm build links with a plain `lld`; use the worker's Nix-provided one.
for candidate in /nix/store/*-lld-22.1.8/bin/lld; do
  if [[ -x "$candidate" ]]; then PATH="$(dirname "$candidate"):$PATH"; break; fi
done
# C code in wasm dependencies (for example ring) needs an unwrapped clang that emits
# wasm objects; the Nix compiler wrapper in the shell does not.
probe=$(mktemp -d)
printf 'int f(void){return 1;}\n' > "$probe/t.c"
for candidate in /nix/store/*-clang-2*/bin/clang; do
  if "$candidate" --target=wasm32-unknown-unknown -c "$probe/t.c" -o "$probe/t.o" 2>/dev/null \
     && [[ "$(head -c4 "$probe/t.o" | od -An -tx1 | tr -d ' \n')" == 0061736d ]]; then
    export CC_wasm32_unknown_unknown="$candidate"; break
  fi
done
rm -rf "$probe"
printf 'wasm cc: %s\n' "${CC_wasm32_unknown_unknown:-none}"
