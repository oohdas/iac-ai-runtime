from pathlib import Path
import json
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sean_os import Actor, SeanOSStore


def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        store = SeanOSStore(Path(directory) / "status.db")
        sean = Actor.sean()
        goal = store.create_record(sean, "GOAL", "IAC", {"name": "2031 exit readiness"}, source="synthetic-status")
        project = store.create_record(sean, "PROJECT", "IAC", {"name": "Canonical database", "goal_id": goal}, source="synthetic-status")
        store.transition_project(sean, project, "ACTIVE", "Milestone 12 implementation")
        package = store.sale_export_package(sean)
        status = {
            "milestone": 12,
            "name": "Secret-safe export and scoped primary-interface CRUD",
            "state": "ACTIVE",
            "integrity": store.integrity_check(),
            "synthetic_records": len(store.list_records(sean)),
            "audit_events": len(store.audit_events()),
            "sale_export_records": package["record_count"],
            "sale_export_sha256": package["sha256"],
            "real_data_connected": False,
            "production_deployed": False,
            "runtime_health": store.runtime_health(),
        }
        print(json.dumps(status, indent=2, sort_keys=True))
        store.close()


if __name__ == "__main__":
    main()
