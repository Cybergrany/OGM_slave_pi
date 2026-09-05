"""Exercise the deployment exporter CLI with both IO source schemas."""

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml


EXPORTER = Path(__file__).resolve().parents[1] / "scripts" / "export_pinmap.py"


class ExportPinmapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.board = {"name": "audio", "address": 41, "zone": 2,
                      "reset_on_init": True, "has_stats": True,
                      "pins": [{"name": "output", "type": "OUTPUT_DIGITAL",
                                "pin": 4, "args": [False]}]}
        self.bridge = {"name": "bridge", "address": 10, "zone": 3,
                       "children": [{"name": "child", "downstream_address": 7,
                                     "has_stats": True, "pins": self.board["pins"]}]}
        self.v1 = {"version": 1, "network_baud": 250000,
                   "boards": [self.board], "bridges": [self.bridge]}
        self.v2 = {"version": 2, "networks": [
            {"name": "primary", "serial": {"baud": 250000},
             "boards": [self.board], "bridges": [self.bridge]}]}
        self.traits = {"version": 1, "traits": [
            {"name": "PIN_HASH", "namespaces": ["master"], "input_regs": 2},
            {"name": "OUTPUT_DIGITAL", "namespaces": ["master"], "coils": 1},
            {"name": "BOARD_STATS", "namespaces": ["master"], "input_regs": 20}]}

    def export(self, config, *selectors, error=None):
        for name, data in (("io", config), ("traits", self.traits),
                           ("custom", {"version": 1})):
            (self.root / f"{name}.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-B", str(EXPORTER),
             "--config", str(self.root / "io.yaml"),
             "--traits", str(self.root / "traits.yaml"),
             "--custom-traits", str(self.root / "custom.yaml"),
             "--output", "-", *selectors], capture_output=True, text=True)
        if error:
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(error, result.stderr)
            self.assertEqual(result.stdout, "")
            return None
        self.assertEqual(result.returncode, 0, result.stderr)
        layout = json.loads(result.stdout)
        layout.pop("generated_at")
        return layout

    def test_v1_v2_board_layout_and_hash_are_identical(self):
        original = self.export(self.v1, "--address", "41")
        self.assertEqual(original, self.export(self.v2, "--address", "41"))
        self.assertEqual(original["schema_version"], 1)
        self.assertEqual(original["totals"], {
            "coils": 1, "discretes": 0, "input_regs": 22, "holding_regs": 0})
        self.assertEqual(original["pins"][0]["args"], [original["hash"]])
        self.v1["version"] = "1"
        self.assertEqual(original, self.export(self.v1, "--name", "audio"))

    def test_v1_v2_child_layout_and_hash_are_identical(self):
        self.assertEqual(
            self.export(self.v1, "--child-address", "7", "--bridge-address", "10"),
            self.export(self.v2, "--child-name", "child", "--network", "primary"))

    def test_repeated_addresses_require_selection_and_use_selected_baud(self):
        second = copy.deepcopy(self.v2["networks"][0])
        second.update(name="secondary", serial={"baud": 115200})
        second["boards"][0]["name"] = "other_audio"
        second["bridges"][0]["name"] = "other_bridge"
        self.v2["networks"].append(second)
        self.export(self.v2, "--address", "41", error="Multiple boards matched")
        selected = self.export(self.v2, "--address", "41", "--network", "secondary")
        self.assertEqual(selected["network_baud"], 115200)
        self.assertEqual(selected["label"], "other_audio")
        self.assertEqual(selected, self.export(self.v2, "--name", "other_audio"))
        self.export(self.v2, "--child-address", "7", error="Multiple bridge children matched")
        child = self.export(self.v2, "--child-address", "7", "--network", "secondary")
        self.assertEqual(child["network_baud"], 115200)
        self.assertEqual(child["bridge"]["name"], "other_bridge")
        self.export(self.v2, "--address", "41", "--network", "missing",
                    error="No matching board")

    def test_invalid_v2_ownership_is_rejected(self):
        cases = []
        for key, value, message in (("serial", {}, "serial.baud"),
                                    ("boards", {}, "boards must be a list")):
            config = copy.deepcopy(self.v2)
            config["networks"][0][key] = value
            cases.append((config, message))
        config = copy.deepcopy(self.v2)
        config["networks"][0]["bridges"][0]["address"] = 41
        cases.append((config, "addresses must be unique"))
        config = copy.deepcopy(self.v2)
        config["networks"][0]["bridges"][0]["name"] = "audio"
        cases.append((config, "names must be globally unique"))
        cases.extend([({"version": 2, "networks": []}, "non-empty networks"),
                      ({**self.v2, "boards": []}, "must be inside networks"),
                      ({"version": 3}, "version: 1 or 2")])
        for config, message in cases:
            with self.subTest(message=message):
                self.export(config, "--address", "41", error=message)

    def test_traits_schema_is_independent(self):
        self.traits["version"] = 2
        self.export(self.v2, "--address", "41", error="traits.yaml must set version: 1")

    def test_skip_external_still_applies(self):
        self.board["external_management"] = True
        self.export(self.v2, "--address", "41", "--skip-external",
                    error="marked external_management")


if __name__ == "__main__":
    unittest.main()
