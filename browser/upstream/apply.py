#!/usr/bin/env python3
"""Apply the pinned source experiment inside isolated CI checkouts.

This script installs no tools and makes no network requests. Build and test the
result separately, preserve its locks/hashes, and never call this on shared work.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile


def git(checkout, *arguments):
    return subprocess.check_output(["git", "-C", str(checkout), *arguments], text=True).strip()


def from_archives(archives, destination, manifest):
    destination = Path(destination).resolve()
    if destination.exists():
        raise SystemExit("archive output must be a new isolated directory")
    verified = []
    for path, section, directory in zip(archives, ("torJs", "arti"), ("tor-js", "arti")):
        archive_argument = Path(path)
        archive = archive_argument.resolve()
        expected = Path(str(archive_argument) + ".sha256").read_text().split()[0]
        if not re.fullmatch(r"[a-fA-F0-9]{64}", expected):
            raise SystemExit("invalid archive digest record")
        digest = hashlib.sha256()
        with archive.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != expected.lower():
            raise SystemExit("archive digest mismatch")
        with archive.open("rb") as source:
            revision = subprocess.check_output(["git", "get-tar-commit-id"], stdin=source, text=True).strip()
        if revision != manifest[section]["revision"]:
            raise SystemExit(f"incorrect {section} archive revision")
        verified.append((archive, destination / directory))
    destination.mkdir(parents=False)
    for archive, checkout in verified:
        checkout.mkdir()
        with tarfile.open(archive, "r:") as source:
            members = source.getmembers()
            if any(".git" in Path(member.name).parts for member in members):
                raise SystemExit("source archive contains Git control files")
            source.extractall(checkout, members=members, filter="data")
        git(checkout, "init", "--quiet")
        git(checkout, "config", "user.name", "cmsg source fixture")
        git(checkout, "config", "user.email", "fixture@invalid")
        git(checkout, "config", "core.hooksPath", "/dev/null")
        git(checkout, "add", "--force", "--all")
        git(checkout, "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "verified source archive baseline")
    return tuple(checkout for _, checkout in verified)


def main():
    source = Path(__file__).resolve().parent
    manifest = json.loads((source / "manifest.json").read_text())
    archived = len(sys.argv) == 6 and sys.argv[1] == "--from-archives"
    if archived:
        stage = sys.argv[5]
    elif len(sys.argv) == 4:
        stage = sys.argv[3]
    else:
        raise SystemExit("usage: apply.py TOR_JS_CHECKOUT ARTI_CHECKOUT STAGE; or apply.py --from-archives TOR_JS_TAR ARTI_TAR NEW_OUTPUT_DIR STAGE")
    if stage not in {"client", "streams", "service", "test-network"}:
        raise SystemExit("stage must be client, streams, service or test-network")
    diagnostic_option = os.environ.get("TOR_DIAGNOSTICS", "0")
    if diagnostic_option not in {"0", "1"}:
        raise SystemExit("TOR_DIAGNOSTICS must be 0 or 1")
    diagnostics = stage == "test-network" or diagnostic_option == "1"
    if diagnostics and stage not in {"service", "test-network"}:
        raise SystemExit("service diagnostics require the service or test-network stage")
    renewal_option = os.environ.get("TOR_RENEWAL", "0")
    if renewal_option not in {"0", "1"}:
        raise SystemExit("TOR_RENEWAL must be 0 or 1")
    renewal = renewal_option == "1"
    if renewal and stage != "test-network":
        raise SystemExit("renewal diagnostics require the private test-network stage")
    if archived:
        tor_js, arti = from_archives(sys.argv[2:4], sys.argv[4], manifest)
    else:
        tor_js, arti = (Path(value).resolve() for value in sys.argv[1:3])
    for checkout, section in [(tor_js, "torJs"), (arti, "arti")]:
        if not archived and git(checkout, "rev-parse", "HEAD") != manifest[section]["revision"]:
            raise SystemExit(f"incorrect {section} source revision")
        if git(checkout, "status", "--porcelain"):
            raise SystemExit(f"{section} checkout must be clean and isolated")

    patches = [(tor_js, "tor-js-onion-client.patch"), (tor_js, "tor-js-gateway-response.patch"),
               (tor_js, "tor-js-gateway-bind.patch")]
    post_overlay_patches = []
    overlays = []
    if stage in {"streams", "service", "test-network"}:
        patches.append((tor_js, "tor-js-onion-stream.patch"))
        overlays.append(("onion_stream.rs", tor_js / "crates/tor-js-wasm/src/onion_stream.rs"))
    if stage in {"service", "test-network"}:
        patches.extend([(arti, "arti-browser-service.patch"), (tor_js, "tor-js-onion-service.patch")])
        patches.append((arti, "arti-publisher-renewal.patch"))
        patches.append((tor_js, "tor-js-full-vanguards.patch"))
        overlays.extend([
            ("state_dir_wasm.rs", arti / "crates/tor-persist/src/state_dir_wasm.rs"),
            ("onion_service.rs", tor_js / "crates/tor-js-wasm/src/onion_service.rs"),
        ])
    if stage == "test-network":
        patches.append((tor_js, "tor-js-test-network.patch"))
        overlays.append(("test_network.rs", tor_js / "crates/tor-js-wasm/src/test_network.rs"))
    if diagnostics:
        patches.extend([(arti, "arti-service-diagnostics.patch"),
                        (arti, "arti-publisher-diagnostics.patch")])
        post_overlay_patches.append((tor_js, "tor-js-service-diagnostics.patch"))
        post_overlay_patches.append((tor_js, "tor-js-publisher-diagnostics.patch"))
    if renewal:
        patches.append((arti, "arti-renewal-diagnostics.patch"))
        post_overlay_patches.append((tor_js, "tor-js-renewal-diagnostics.patch"))
    for checkout, patch in patches:
        git(checkout, "apply", "--check", str(source / patch))
        git(checkout, "apply", str(source / patch))
    for overlay, target in overlays:
        shutil.copyfile(source / overlay, target)
    for checkout, patch in post_overlay_patches:
        git(checkout, "apply", "--check", str(source / patch))
        git(checkout, "apply", str(source / patch))

    # Every direct Arti dependency must use the same sibling checkout. Replacing
    # only selected crates mixes git/path Runtime types and is not a valid build.
    revision = re.escape(manifest["arti"]["revision"])
    pattern = re.compile(
        r'(?m)^([A-Za-z0-9_-]+)(\s*=\s*\{\s*)git = "https://github\.com/voltrevo/arti", '
        r'rev = "' + revision + r'"'
    )
    replacements = 0
    for cargo in tor_js.rglob("Cargo.toml"):
        def replace(match):
            crate = arti / "crates" / match.group(1)
            if not (crate / "Cargo.toml").is_file():
                raise SystemExit("unrecognized pinned Arti dependency")
            path = os.path.relpath(crate, cargo.parent).replace(os.sep, "/")
            return match.group(1) + match.group(2) + "path = " + json.dumps(path)
        contents, count = pattern.subn(replace, cargo.read_text())
        if count:
            cargo.write_text(contents)
            replacements += count
    if replacements < 10:
        raise SystemExit("unexpected pinned dependency layout")
    inputs = [patch for _, patch in patches + post_overlay_patches] + [overlay for overlay, _ in overlays]
    print(json.dumps({
        "stage": stage,
        "testNetworkOnly": stage == "test-network",
        "serviceDiagnostics": diagnostics,
        "renewalDiagnostics": renewal,
        "sourceMode": "verified git archives" if archived else "pinned git checkouts",
        "torJsRevision": manifest["torJs"]["revision"],
        "artiRevision": manifest["arti"]["revision"],
        "localArtiDependencies": replacements,
        "inputsSha256": {name: hashlib.sha256((source / name).read_bytes()).hexdigest() for name in inputs},
        "evidence": "source application only; compile, browser and Tor network evidence required",
    }, sort_keys=True))


if __name__ == "__main__":
    main()
