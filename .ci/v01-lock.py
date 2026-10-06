"""Keep the compatible Strum edge inside derive-deftly's declared version range.

Crow204/8 selected strum0.25 with itertools0.14; the generated EnumIter::get
collides with Itertools::get. The maintained Tor graph already uses strum0.28.
Both packages can coexist (passkey-types still needs0.25). No registry package,
checksum, source, compiler or shared cache is replaced by this selection.
"""
import pathlib
import re
import tomllib

path = pathlib.Path("Cargo.lock")
source = path.read_text()
packages = tomllib.loads(source)["package"]
if not any(p["name"] == "strum" and p["version"] == "0.28.0" for p in packages):
    raise SystemExit("expected the maintained Tor Strum package in the resolved graph")
pattern = r'(\[\[package\]\]\nname = "derive-deftly-macros"\nversion = "1\.11\.5"\n.*?)(?=\n\[\[|\Z)'
matches = list(re.finditer(pattern, source, re.S))
if len(matches) != 1:
    raise SystemExit("derive-deftly changed; review this compatibility selection")
match = matches[0]
block = match.group(0)
old = re.findall(r'"strum [0-9.]+"', block)
if len(old) != 1:
    raise SystemExit("expected one explicit derive-deftly Strum edge")
replacement = block.replace(old[0], '"strum 0.28.0"')
path.write_text(source[:match.start()] + replacement + source[match.end():])
