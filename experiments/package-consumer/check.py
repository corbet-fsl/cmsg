#!/usr/bin/env python3
"""Inspect a crate and execute its external consumer on the CI worker only.

The caller first verifies an immutable Git archive. An expected commit argument
alone does not authenticate source; packaged bytes are compared to that checkout.
No install, publication, production key, provider or network service is involved.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib


def require(condition, message):
    if not condition:
        raise ValueError(message)


def dependency(spec):
    if isinstance(spec, str):
        return {"version": spec}
    return spec


def check_manifest(original, normalized):
    for key in (
        "name", "version", "edition", "rust-version", "description", "repository",
        "license-file", "readme", "publish",
    ):
        require(original["package"].get(key) == normalized["package"].get(key),
                f"normalized package field changed: {key}")
    require(normalized["package"].get("build") in (None, False), "unexpected build script")
    require(normalized.get("lib", {}).get("path") == "src/lib.rs", "unexpected library path")
    require(not normalized.get("bin"), "unexpected binary target")
    require(not normalized.get("patch") and not normalized.get("replace"),
            "unexpected dependency override")
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        old = original.get(section, {})
        new = normalized.get(section, {})
        require(old.keys() == new.keys(), f"normalized dependency set changed: {section}")
        for name in old:
            left, right = dependency(old[name]), dependency(new[name])
            for key in ("version", "package", "registry", "path", "git", "branch", "tag", "rev"):
                require(left.get(key) == right.get(key), f"dependency source changed: {name}/{key}")
            for key, default in (("default-features", True), ("optional", False)):
                require(left.get(key, default) == right.get(key, default),
                        f"dependency setting changed: {name}/{key}")
            require(sorted(left.get("features", [])) == sorted(right.get("features", [])),
                    f"dependency features changed: {name}")


def allowed(path):
    if path in {"Cargo.toml", "Cargo.toml.orig", "Cargo.lock", "LICENSE.md", "README.md",
                ".cargo_vcs_info.json"}:
        return True
    parts = PurePosixPath(path).parts
    if parts[0] in {"src", "tests"}:
        return path.endswith(".rs") or path == "tests/fixtures/admission-v1.json"
    if parts[0] == "examples":
        return len(parts) == 2 and path.endswith(".rs")
    return parts[0] in {"docs", "studies", "experiments"} and path.endswith(".md")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()
    require(re.fullmatch(r"[a-f0-9]{40}", args.expected_commit), "invalid expected commit")
    archive = args.archive.resolve(strict=True)
    source = Path(__file__).resolve().parents[2]
    original = tomllib.loads((source / "Cargo.toml").read_text())
    package = original["package"]
    prefix = f"{package['name']}-{package['version']}"
    require(archive.name == f"{prefix}.crate", "archive name differs from source metadata")
    require(archive.stat().st_size <= 16 * 1024 * 1024, "unexpected archive size")

    with tempfile.TemporaryDirectory(prefix="cmsg-package-consumer-") as owned:
        root = Path(owned)
        unpacked = root / "unpacked"
        unpacked.mkdir()
        included = set()
        total_size = 0
        with tarfile.open(archive, "r:gz") as bundle:
            for entry in bundle:
                pieces = PurePosixPath(entry.name).parts
                require(pieces and pieces[0] == prefix and ".." not in pieces,
                        "archive path escapes package root")
                require("\\" not in entry.name, "nonportable archive path")
                if entry.isdir():
                    continue
                require(entry.isfile() and len(pieces) > 1, "archive contains a link or special file")
                relative = PurePosixPath(*pieces[1:]).as_posix()
                require(allowed(relative), f"unexpected packaged file: {relative}")
                require(relative not in included, "duplicate archive path")
                included.add(relative)
                total_size += entry.size
                require(len(included) <= 500 and 0 <= entry.size <= 8 * 1024 * 1024
                        and total_size <= 32 * 1024 * 1024, "unexpected unpacked package size")
                content = bundle.extractfile(entry).read()
                target = unpacked / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
                if relative == "Cargo.toml":
                    continue  # Cargo-normalized metadata is checked below.
                if relative == ".cargo_vcs_info.json":
                    vcs = json.loads(content)
                    require(vcs["git"]["sha1"] == args.expected_commit
                            and not vcs["git"].get("dirty", False), "Cargo VCS metadata differs")
                elif relative == "Cargo.lock":
                    require(tomllib.loads(content.decode()) == tomllib.loads((source / relative).read_text()),
                            "packaged lock differs from verified checkout")
                else:
                    local = "Cargo.toml" if relative == "Cargo.toml.orig" else relative
                    require((source / local).read_bytes() == content,
                            f"packaged bytes differ from verified checkout: {relative}")
        require({"Cargo.toml", "Cargo.toml.orig", "Cargo.lock", "LICENSE.md", "README.md",
                 "src/lib.rs", "src/member.rs", "src/inbox.rs", "src/transport.rs"} <= included,
                "package is missing required files")
        check_manifest(original, tomllib.loads((unpacked / "Cargo.toml").read_text()))

        consumer = root / "consumer"
        consumer.mkdir()
        companions = Path(__file__).resolve().parent
        shutil.copyfile(companions / "Cargo.toml", consumer / "Cargo.toml")
        shutil.copytree(companions / "src", consumer / "src")
        # Preserve the exact tested dependency graph. Only add this external root;
        # do not resolve newer cached or registry dependency versions.
        lock_bytes = (unpacked / "Cargo.lock").read_text()
        lock = tomllib.loads(lock_bytes)
        core = next(p for p in lock["package"] if p["name"] == package["name"]
                    and p["version"] == package["version"] and "source" not in p)
        dependencies = ["cmsg"]
        for name in ("data-encoding", "ed25519-dalek", "serde_json", "sha2"):
            dependencies.append(next(d for d in core["dependencies"] if d.split(" ")[0] == name))
        addition = '\n[[package]]\nname = "cmsg-package-consumer"\nversion = "0.0.0"\n'
        addition += "dependencies = " + json.dumps(dependencies) + "\n"
        (consumer / "Cargo.lock").write_text(lock_bytes + addition)
        subprocess.run(["cargo", "run", "--locked", "--offline", "--manifest-path",
                        str(consumer / "Cargo.toml")], cwd=root, check=True)
        print(json.dumps({
            "archive": archive.name,
            "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "files": len(included),
            "unpacked_bytes": total_size,
            "verified_checkout_files_match": True,
            "expected_source_commit": args.expected_commit,
            "cargo_vcs_metadata_present": ".cargo_vcs_info.json" in included,
            "external_consumer": True,
        }, sort_keys=True))


if __name__ == "__main__":
    main()
