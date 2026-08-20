#!/usr/bin/env python3
"""Fail-closed release verification for the independently owned IAC runtime."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BRIDGE_SCHEMA_SHA256 = "70f271353b4e6696ada8816f6bad821cfabaec4e87aa96edaae97a14ac7f41d8"


def run(label: str, command: list[str]) -> dict[str, object]:
    completed = subprocess.run(command, cwd=ROOT, check=False)
    if completed.returncode:
        raise SystemExit(f"{label} failed with exit code {completed.returncode}")
    return {"check": label, "passed": True}


def main() -> int:
    checks: list[dict[str, object]] = []
    schema = ROOT / "bridge-contract.schema.json"
    digest = hashlib.sha256(schema.read_bytes()).hexdigest()
    if digest != BRIDGE_SCHEMA_SHA256:
        raise SystemExit("bridge contract changed without an explicit version/hash update")
    checks.append({"check": "bridge_contract_sha256", "passed": True, "sha256": digest})
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    if "USER sean-os" not in dockerfile or "VOLUME [\"/data\"]" not in dockerfile:
        raise SystemExit("container must run non-root with explicit persistent data volume")
    checks.append({"check": "container_safety_invariants", "passed": True})
    workflow = (ROOT / ".github/workflows/verify.yml").read_text(encoding="utf-8")
    if "contents: read" not in workflow or "docker build" not in workflow:
        raise SystemExit("continuous verification must be read-only and build the container")
    if "docker push" in workflow or "railway up" in workflow:
        raise SystemExit("verification workflow must not publish or deploy")
    checks.append({"check": "workflow_permissions_and_no_deploy", "passed": True})
    checks.append(run("compile", [sys.executable, "-m", "compileall", "-q", "sean_os", "tests"]))
    checks.append(run("tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]))
    checks.append(run("recovery_drill", [sys.executable, "scripts/recovery_drill.py"]))
    print(json.dumps({"passed": True, "checks": checks}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
