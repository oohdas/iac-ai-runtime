from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sean_os import Actor, SeanOSStore


with tempfile.TemporaryDirectory() as directory:
    store = SeanOSStore(Path(directory) / "sean-os-demo.db")
    sean = Actor.sean()
    goal = store.create_record(
        sean, "GOAL", "IAC",
        {"name": "Prepare IAC for a desirable 2031 exit", "target_year": 2031},
        source="synthetic-demo",
    )
    project = store.create_record(
        sean, "PROJECT", "IAC",
        {"name": "Capture pricing knowledge", "goal_id": goal},
        source="synthetic-demo",
    )
    store.transition_project(sean, project, "ACTIVE", "High transferability impact")
    print(f"Created goal: {goal}")
    print(f"Created active project: {project}")
    print(f"Sale-export records: {len(store.sale_export(sean))}")
    print(f"Audit events: {len(store.audit_events())}")
    store.close()
