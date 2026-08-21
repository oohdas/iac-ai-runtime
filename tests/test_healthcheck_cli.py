import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sean_os import SeanOSStore


ROOT = Path(__file__).resolve().parents[1]


class HealthcheckCliTests(unittest.TestCase):
    def test_iac_profile_opens_iac_database_and_reports_active_worker(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "iac-health.db"
            store = SeanOSStore(database, scope_profile="IAC")
            try:
                store.heartbeat("test-worker", "IAC", "IDLE")
            finally:
                store.close()

            result = subprocess.run(
                [
                    sys.executable,
                    "scripts/healthcheck.py",
                    "--database",
                    str(database),
                    "--scope-profile",
                    "IAC",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            health = json.loads(result.stdout)
            self.assertTrue(health["healthy"])
            self.assertEqual(health["active_worker_count"], 1)
            self.assertEqual(health["workers"][0]["owner_scope"], "IAC")


if __name__ == "__main__":
    unittest.main()
