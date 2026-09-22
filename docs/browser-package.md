# Browser package build and validation

[Browser package entrypoint](../browser/README.md).

Build the Rust library for `wasm32-unknown-unknown`, then generate the Web
bindings with a `wasm-bindgen` CLI matching the resolved crate version, output
name `cmsg`, into `browser/pkg/`. Copy the repository license into the package
before packing. The checked-in package excludes generated artifacts.

After generating those bindings, `node .ci/browser-package.mjs <artifact-directory>`
creates and checks an installable npm archive with the license, runtime entrypoints,
declarations and Wasm binary. The archive includes the exact Tor dependency
manifest; patch/build tooling and validation fixtures remain in the
[source repository](https://github.com/cmtymeet/cmsg/tree/main/browser/upstream).
The optional Tor entrypoints require the separately built, patched TorJS artifact
described there; packaging cmsg does not install the stock TorJS package.

`tests/browser.rs` runs in a real browser using `wasm-bindgen-test` and covers
binary/text MLS round-trips, authentication failures, replay rejection,
encrypted restore, and the portable route/framing bindings.

The generated-JavaScript ABI contract is `browser/contract.mjs`. Serve the
repository root after generating `browser/pkg`, then run in a real browser:
`await import('/browser/contract.mjs').then(m => m.runBrowserContract())`.
It returns `{ evidence, passed, profileComposition }` or throws on failure;
`profileComposition` is undefined unless the pinned cfrm adapter is supplied. It exercises real
WebCrypto, Wasm and IndexedDB transactions, plus separately labeled scripted
transport failure cases; it does not claim live Tor connectivity.

The shared portable browser CI suite additionally requires the exact cfrm
profile archive recorded in `.ci/archives.toml` and runs its actual profile
clients against cmsg's generated signing bindings. The console invocation above
alone does not run that composition. See [profile signing](profile-signing.md)
for the required source inputs, recorded evidence and synthetic-gate limits.
