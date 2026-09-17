# Browser Tor dependency snapshot

These locks preserve the dependency graph validated by cmsg Crow run 68 at
`b23221271f7170a4f665e3834f4302a4a1a33ff0`. They were downloaded from that run's
artifacts and checked against its SHA256SUMS before editing. Original digests:

- `tor-js-Cargo.lock`: `772feb2c7c7ab3a8352f196c0876c889660171e2ff950e940b0a1792fb9a91a4`.
- `arti-Cargo.lock`: `66dbb07f67e9a6d483b9915b8680b50f5c5a9303006b7d9959ea40c9c7ee983c`.

The TorJS lock then adds only a direct dependency edge from `tor-js` to the
already pinned `tor-guardmgr 0.44.0`, used to select full vanguards explicitly.
No package version, source or checksum changes. The locked CI build validates
that this edited graph matches the patched source manifests.

The upstream source revisions remain in `../manifest.json`. Paths refer to
the isolated sibling TorJS/Arti source trees created by `apply.py`. Public
network validation consumes these locks with `--locked`; it does not claim a
fresh dependency resolution. The private fixture retains its existing resolver
workflow. Dependency changes require a deliberate replacement and validation.
