from pathlib import Path
import json
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sean_os import Actor, SeanOSStore


def main() -> int:
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory); source=root / "source.db"
        store=SeanOSStore(source); sean=Actor.sean()
        sentinel=store.create_record(
            sean, "KNOWLEDGE", "IAC", {"name":"synthetic recovery sentinel"},
            source="recovery-drill",
        )
        manifest=store.backup_manifest(sean, root / "backup.db")
        restored_path=store.restore_backup(sean, root / "backup.db", root / "restored.db")
        restored=SeanOSStore(restored_path)
        recovered=restored.get_record(sean, sentinel)["payload"]["name"]
        integrity=restored.integrity_check()
        restored.close(); store.close()
        result={"passed":integrity["ok"] and recovered == "synthetic recovery sentinel",
                "backup":manifest, "restored_integrity":integrity,
                "sentinel_recovered":recovered == "synthetic recovery sentinel"}
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
