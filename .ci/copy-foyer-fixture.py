"""Import real owner fixtures from the exact resolved server source."""
import json
import hashlib
import os
import re
import shutil
from pathlib import Path

metadata = json.loads(Path("fixture-metadata.json").read_text())
owners = [package for package in metadata["packages"] if package["name"] == "cvld"]
if len(owners) != 1:
    raise SystemExit("Expected exactly one resolved door owner")
owner = owners[0]
runtime = json.loads(Path("runtime-metadata.json").read_text())
# The production client reaches the door through cvld's client half: the package `cvld-client` (split out of
# `cvld` on 2026-11-09) or, in older graphs, `cvld` itself. Either way it must come from the door owner's source.
DOOR_CLIENT_NAMES = ("cvld", "cvld-client")
client_owners = [p for p in runtime["packages"] if p["name"] in DOOR_CLIENT_NAMES]
candidate = None
if os.environ.get('CHECKS') == 'browser-package-candidates':
    from browser_candidates import candidate_door, sha
    candidate = candidate_door(owner, client_owners)
else:
    # The lock names the door owner by its canonical forge path (corbet-libs -> corbet-fsl on 2026-11-09) and
    # carries the `.git` suffix; accept both spellings so a lock refreshed before or after the move passes.
    if not re.fullmatch(r"git\+https://git\.corbet\.ch/corbet-(?:libs|fsl)/cvld(?:\.git)?\?branch=main#[0-9a-f]{40}", owner["source"]):
        raise SystemExit("Expected a resolved main revision of the door owner")
    # One package per name, every one of them from exactly the fixture's door source.
    client_names = [p["name"] for p in client_owners]
    if not client_owners or len(set(client_names)) != len(client_names) or any(p["source"] != owner["source"] for p in client_owners):
        raise SystemExit("Fixture and production client must use exactly the same door source")
source = Path(owner["manifest_path"]).parent.resolve()
destination = Path("tests/fixture/owner")
destination.mkdir(parents=True, exist_ok=True)
names = ["mod.rs", "resident.rs", "client_faults.rs", "active.rs", "self_ban.rs"]
for name in names:
    fixture = (source / "tests/support" / name).resolve()
    if not fixture.is_relative_to(source):
        raise SystemExit("Owner fixture escapes its source directory")
    shutil.copyfile(fixture, destination / name)
    if candidate and sha(destination / name) != candidate['required_fixture_files']['tests/support/' + name]:
        raise SystemExit('Copied original candidate fixture differs')
receipt = {"source": owner["source"], "files": names}
if not candidate:
    # The one reviewed assembler of the native accounting operator configuration (cvld owns
    # its schema). Missing from the resolved revision means the account journey cannot run.
    tool = (source / "tools/g5-account-config.py").resolve()
    if not tool.is_relative_to(source) or not tool.is_file():
        raise SystemExit("The resolved door owner has no G5 account configuration assembler")
    shutil.copyfile(tool, destination / "g5-account-config.py")
    receipt["g5_account_config"] = hashlib.sha256(tool.read_bytes()).hexdigest()
if not candidate:
    # Reuse this exact server owner's existing native build environment.
    shell = (source / ".ci/check-shell.nix").resolve()
    if not shell.is_relative_to(source):
        raise SystemExit("Owner build shell escapes its source directory")
    source_hash = hashlib.sha256(shell.read_bytes()).hexdigest()
    copied_shell = destination / "check-shell.nix"
    shutil.copyfile(shell, copied_shell)
    copied_hash = hashlib.sha256(copied_shell.read_bytes()).hexdigest()
    if copied_hash != source_hash:
        raise SystemExit("Copied original owner build shell differs")
    receipt["build_shell"] = {
        "source_path": ".ci/check-shell.nix",
        "sha256": copied_hash,
    }
if candidate:
    receipt.update(candidate=candidate, manifest_path=owner['manifest_path'], package_id=owner['id'])
Path("fixture-owner.json").write_text(json.dumps(receipt, indent=2) + "\n")
