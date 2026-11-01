import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from vmspec.__main__ import main
from vmspec.config import load_config
from vmspec.model import RegionKind


class ConfigTests(unittest.TestCase):
    def config(self):
        return {"vpc": "esi", "vsp": "edi", "base_addr": 0x4000,
                "handlers": [{"opcode": 1, "entry": 0x4000, "end": 0x4014}]}

    def test_readonly_and_dispatcher_ranges(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            config = self.config()
            config["regions"] = [{"name": "ro", "kind": "readonly", "base": 0x2000, "size": 8}]
            config["dispatcher_ranges"] = [[0x4014, 4]]
            path.write_text(json.dumps(config))
            parsed = load_config(str(path))
            self.assertEqual(parsed.vm_state.regions[0].kind, RegionKind.READONLY)
            self.assertEqual(parsed.vm_state.dispatcher_ranges, [(0x4014, 4)])
            config["dispatcher_ranges"] = [[0x4014, -1]]
            path.write_text(json.dumps(config))
            with self.assertRaisesRegex(ValueError, "dispatcher_ranges"):
                load_config(str(path))

    def test_cli_generates_clear_branch_from_native_handler(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.json"
            binary = Path(tmp) / "handler.bin"
            spec = Path(tmp) / "generated.slaspec"
            config_path.write_text(json.dumps(self.config()))
            binary.write_bytes(bytes.fromhex("8b0685c07408c70701000000eb06c7070200000090"))
            with contextlib.redirect_stderr(io.StringIO()):
                result = main([str(binary), str(config_path), "--max-steps", "8",
                               "--out", str(spec)])
            self.assertEqual(result, 0)
            self.assertIn("is byte = 0x01", spec.read_text())
            self.assertIn("goto <node_", spec.read_text())


if __name__ == "__main__":
    unittest.main()
