"""Pure artifact/source selector adversaries; never run Tor, Rust or a fixture."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("private_tor_journey", Path(__file__).with_name("private-tor-journey.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Selection(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = "git+https://git.corbet.ch/corbet-foss/ctrn.git?branch=v01#" + "a" * 40
        (self.root / "Cargo.toml").touch()
        (self.root / "Cargo.lock").write_text(f'[[package]]\nname="ctrn"\nversion="0.0.0"\nsource="{self.source}"\n')
        self.owner = self.root / "owner"
        (self.owner / ".ci").mkdir(parents=True)
        (self.owner / "Cargo.toml").touch()
        self.script = self.owner / ".ci/private-network.py"
        self.script.write_bytes(b"inert selector input; never executed")
        self.digest = module.hashlib.sha256(self.script.read_bytes()).hexdigest()
        self.target = self.root / "target"
        self.target.mkdir()
        self.executable = self.target / "test-binary"
        self.executable.touch(mode=0o700)
        self.metadata = {"packages":[
            {"name":"ctrn","version":"0.0.0","source":self.source,"manifest_path":str(self.owner / "Cargo.toml")},
            {"name":"cmsg","id":"consumer","manifest_path":str(self.root / "Cargo.toml")}
        ], "target_directory":str(self.target)}
        self.artifact = {"reason":"compiler-artifact","package_id":"consumer",
                         "target":{"name":"initial_tor","kind":["test"]},
                         "profile":{"test":True},"executable":str(self.executable)}

    def choose(self, artifacts=None):
        # Only these inert selector bytes replace the hash within this pure test.
        # Production keeps the reviewed original fixture hash and invokes no shim.
        with patch.object(module, "SCRIPT_SHA256", self.digest):
            return module.inputs(self.root,self.metadata,artifacts or [self.artifact])

    def test_exact_original_identity_and_actual_test_receipt_selected(self):
        source, script, target, executable = self.choose()
        self.assertEqual((source,script,target,executable),(self.source,self.script,self.target,self.executable))

    def test_wrong_source_lock_and_duplicate_owner_refuse(self):
        for source in [self.source.replace("v01","main"),self.source.replace("git.corbet.ch","github.com"),
                       self.source.replace("a"*40,"b"*40)]:
            with self.subTest(source=source):
                self.metadata["packages"][0]["source"] = source
                with self.assertRaises(ValueError):self.choose()
        self.metadata["packages"][0]["source"] = self.source
        self.metadata["packages"].append(dict(self.metadata["packages"][0]))
        with self.assertRaises(ValueError):self.choose()

    def test_changed_original_script_and_symlink_escape_refuse(self):
        with self.assertRaises(ValueError):module.inputs(self.root,self.metadata,[self.artifact])
        self.script.unlink()
        outside = self.root / "outside.py"
        outside.write_bytes(b"inert selector input; never executed")
        self.script.symlink_to(outside)
        with self.assertRaises(ValueError):self.choose()

    def test_foreign_non_test_duplicate_missing_or_outside_binary_refuse(self):
        for field,value in [("package_id","foreign"),("target",{"name":"other","kind":["test"]}),
                            ("profile",{"test":False}),("executable",None)]:
            with self.subTest(field=field):
                artifact = dict(self.artifact);artifact[field]=value
                with self.assertRaises(ValueError):self.choose([artifact])
        with self.assertRaises(ValueError):self.choose([self.artifact,self.artifact])
        artifact = dict(self.artifact);artifact["executable"] = str(self.root / "outside-binary")
        Path(artifact["executable"]).touch(mode=0o700)
        with self.assertRaises(ValueError):self.choose([artifact])
        os.chmod(self.executable,0o600)
        with self.assertRaises(ValueError):self.choose()


if __name__ == "__main__":
    unittest.main()
