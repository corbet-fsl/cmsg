# v01 integration

`Cargo.toml` is the single candidate selection. Its first-party Git patches
select library `v01` branches on `https://git.corbet.ch`; those branches contain
current main plus rebased product work. No source bundles or qualifier branches
are required. Retain the resolved Cargo.lock from each Crow run.

The repository-owned `v01-push` job runs automatically on every push to a
`v01` branch, including first-party dependency branch pushes. It uses
the CI cache and compiler, with a bounded
job lock and two Cargo workers by default. It resolves once, checks all targets,
runs Clippy with warnings denied and executes unit tests. No browser, Tor
network or coverage runs are part of this loop. Main's verify job is unchanged.
A fast pass is compilation/unit evidence only; real A/B journeys remain the
milestone gates.

Cargo ignores patches inside a Git dependency's manifest. The Cmeet milestone
runner must extract this exact committed manifest's `[patch]` table into a
job-local Cargo config and pass it to Cargo when Cmeet is the root package.
Cmeet depends directly on cmsg's Forgejo `v01` branch. The extracted table is
mechanical input from this one selection, never another maintained owner list.
