"""Import real owner fixtures from the exact resolved server source."""
import json
import re
import shutil
from pathlib import Path

metadata = json.loads(Path("fixture-metadata.json").read_text())
owners = [package for package in metadata["packages"] if package["name"] == "cvld"]
if len(owners) != 1:
    raise SystemExit("Expected exactly one resolved door owner")
owner = owners[0]
if not re.fullmatch(r"git\+https://github\.com/corbet-libs/cvld\?branch=main#[0-9a-f]{40}", owner["source"]):
    raise SystemExit("Expected a resolved main revision of the door owner")
runtime = json.loads(Path("runtime-metadata.json").read_text())
client_owners = [p for p in runtime["packages"] if p["name"] == "cvld"]
if len(client_owners) != 1 or client_owners[0]["source"] != owner["source"]:
    raise SystemExit("Fixture and production client must use exactly the same door source")
source = Path(owner["manifest_path"]).parent.resolve()
destination = Path("tests/fixture/owner")
destination.mkdir(parents=True, exist_ok=True)
names = ["mod.rs", "resident.rs", "client_faults.rs"]
for name in names:
    fixture = (source / "tests/support" / name).resolve()
    if not fixture.is_relative_to(source):
        raise SystemExit("Owner fixture escapes its source directory")
    shutil.copyfile(fixture, destination / name)
Path("fixture-owner.json").write_text(json.dumps({"source": owner["source"], "files": names}, indent=2) + "\n")
