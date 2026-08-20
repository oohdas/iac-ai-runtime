import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class WorkerCliTests(unittest.TestCase):
    def test_integrated_monitoring_is_disabled_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [
                    sys.executable, "scripts/worker.py", "--once", "--database",
                    str(Path(directory) / "default.db"),
                ],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")

    def test_partial_monitoring_contract_fails_startup(self):
        result = subprocess.run(
            [sys.executable, "scripts/worker.py", "--once", "--monitor-route-id", "iac"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("complete route contract", result.stderr)

    def test_complete_monitoring_contract_stays_non_delivering(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [
                    sys.executable, "scripts/worker.py", "--once", "--database",
                    str(Path(directory) / "enabled.db"), "--monitor-route-id",
                    "iac-operator", "--monitor-destination-kind", "EMAIL",
                    "--monitor-destination-ref", "iac-ops-alias",
                ],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            snapshot = json.loads(result.stdout)
            self.assertTrue(snapshot["healthy"])
            self.assertFalse(snapshot["delivery_authorized"])


if __name__ == "__main__":
    unittest.main()
