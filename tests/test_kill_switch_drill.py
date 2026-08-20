from pathlib import Path
import tempfile
import unittest

from scripts.kill_switch_drill import run_drill


class KillSwitchDrillTests(unittest.TestCase):
    def test_synthetic_drill_blocks_and_recovers(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run_drill(Path(directory) / "drill.db")

        self.assertTrue(result["passed"])
        self.assertTrue(result["synthetic_only"])
        self.assertTrue(result["blocked_while_enabled"])
        self.assertTrue(result["recovered_after_disable"])
        self.assertTrue(result["audit_evidence_present"])


if __name__ == "__main__":
    unittest.main()
