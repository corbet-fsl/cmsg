"""Reuse the exact resolved verifier owner's authenticated native SDK shell."""
import hashlib
import json
import re
import shutil
from pathlib import Path

metadata = json.loads(Path("dependency-metadata.json").read_text())
owners = [p for p in metadata["packages"] if p["name"] == "czkp"]
if len(owners) != 1:
    raise SystemExit("Expected exactly one resolved original verifier owner")
owner = owners[0]
if not re.fullmatch(
    r"git\+https://git\.corbet\.ch/corbet-libre/czkp\.git\?branch=main#[0-9a-f]{40}",
    owner.get("source", ""),
):
    raise SystemExit("Expected the canonical resolved verifier owner")
source = Path(owner["manifest_path"]).parent.resolve()
names = ("check-shell.nix", "native-sdk.json")
files = {}
for name in names:
    path = (source / ".ci" / name).resolve()
    if not path.is_relative_to(source):
        raise SystemExit("Verifier SDK input escapes its source directory")
    files[name] = path.read_bytes()
sdk = json.loads(files["native-sdk.json"])
if sdk != {
    "version": "5.2.1",
    "sha256": "e6433e4c0d58d5997b99191d2dde85abd53f119c6f6988ef2b761649ef1b20e5",
}:
    raise SystemExit("Original native SDK declaration differs from the owned prover")
packages = [p for p in metadata["packages"] if p["name"] == "barretenberg-rs"]
if len(packages) != 1 or packages[0]["version"] != sdk["version"]:
    raise SystemExit("Resolved maintained Rust SDK differs from its authenticated native artifact")
destination = Path("native-prover-owner")
destination.mkdir(exist_ok=True)
receipt = {"source": owner["source"], "files": {}}
for name in names:
    original = source / ".ci" / name
    copied = destination / name
    shutil.copyfile(original, copied)
    digest = hashlib.sha256(files[name]).hexdigest()
    if hashlib.sha256(copied.read_bytes()).hexdigest() != digest:
        raise SystemExit("Copied original SDK input differs")
    receipt["files"][".ci/" + name] = digest
encoded = json.dumps(receipt, indent=2) + "\n"
Path("native-prover-owner.json").write_text(encoded)
print(encoded, end="")
