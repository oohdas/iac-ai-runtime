"""Exercise the runtime kill switch against an isolated synthetic database."""

from pathlib import Path
import json
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sean_os import Actor, SeanOSStore


def run_drill(database: Path) -> dict[str, object]:
    store = SeanOSStore(database, scope_profile="IAC")
    sean = Actor.sean()
    worker = Actor("kill-switch-drill-worker", frozenset({"IAC"}))
    work_id = store.enqueue_work(
        sean,
        "NOOP",
        "IAC",
        {"synthetic": True, "source": "kill-switch-drill"},
    )

    store.set_kill_switch(sean, True)
    blocked_claim = store.claim_work(worker, "kill-switch-drill-worker")
    blocked_health = store.runtime_health()

    store.set_kill_switch(sean, False)
    recovered_claim = store.claim_work(worker, "kill-switch-drill-worker")
    recovered_health = store.runtime_health()
    audit_actions = [event["action"] for event in store.audit_events()]
    store.close()

    passed = (
        blocked_claim is None
        and blocked_health["kill_switch"] is True
        and recovered_claim is not None
        and recovered_claim["id"] == work_id
        and recovered_health["kill_switch"] is False
        and audit_actions.count("SET_KILL_SWITCH") == 2
        and "CLAIM_WORK" in audit_actions
    )
    return {
        "passed": passed,
        "synthetic_only": True,
        "blocked_while_enabled": blocked_claim is None,
        "recovered_after_disable": recovered_claim is not None,
        "audit_evidence_present": audit_actions.count("SET_KILL_SWITCH") == 2,
    }


def main() -> int:
    with tempfile.TemporaryDirectory() as directory:
        result = run_drill(Path(directory) / "kill-switch-drill.db")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
