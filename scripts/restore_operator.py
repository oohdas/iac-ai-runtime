#!/usr/bin/env python3
"""Stage, review, and change isolated-restore state without executing a restore."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sean_os import (  # noqa: E402
    Actor,
    AuthorizationError,
    BackupRestoreError,
    BackupRestoreOperatorError,
    SeanOSStore,
    ValidationError,
    authorize_exact_restore_state,
    build_backup_restore_key_approval_package,
    build_isolated_backup_restore_plan,
    decide_exact_restore_approval,
    request_exact_restore_approval,
    review_backup_restore,
    synthetic_backup_restore_preflight,
)


def _read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Hash-bound state-only operator workflow for an isolated IAC restore"
    )
    subparsers = parser.add_subparsers(dest="operation", required=True)
    stage = subparsers.add_parser("stage")
    stage.add_argument("database", type=Path)
    stage.add_argument("upload_plan", type=Path)
    stage.add_argument("upload_receipt", type=Path)
    stage.add_argument("restore_key_proposal", type=Path)
    stage.add_argument("--restore-target-ref", required=True)
    stage.add_argument("--window-start", required=True)
    stage.add_argument("--window-end", required=True)
    stage.add_argument("--max-cost-cad", required=True, type=float)

    def common(name: str) -> argparse.ArgumentParser:
        command = subparsers.add_parser(name)
        command.add_argument("database", type=Path)
        command.add_argument("restore_plan_sha256")
        return command

    common("review")
    request = common("request")
    request.add_argument("--expected-review-sha256", required=True)
    request.add_argument("--expires-at", required=True)
    decide = common("decide")
    decide.add_argument("approval_id")
    decide.add_argument("--expected-review-sha256", required=True)
    decision = decide.add_mutually_exclusive_group(required=True)
    decision.add_argument("--approve", action="store_true")
    decision.add_argument("--deny", action="store_true")
    decide.add_argument("--reason", required=True)
    authorize = common("authorize")
    authorize.add_argument("approval_id")
    authorize.add_argument("--expected-review-sha256", required=True)
    authorize.add_argument("--confirm-plan-sha256", required=True)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    store = SeanOSStore(arguments.database, scope_profile="IAC")
    try:
        if arguments.operation == "stage":
            actor = Actor("iac-restore-interface", frozenset({"IAC"}))
            upload_plan = _read(arguments.upload_plan)
            upload_receipt = _read(arguments.upload_receipt)
            key_package = build_backup_restore_key_approval_package(
                _read(arguments.restore_key_proposal)
            )
            plan = build_isolated_backup_restore_plan(
                upload_plan,
                upload_receipt,
                key_package,
                restore_target_ref=arguments.restore_target_ref,
                window_start=arguments.window_start,
                window_end=arguments.window_end,
                max_cost_cad=arguments.max_cost_cad,
            )
            staged = store.stage_backup_restore(
                actor, plan, upload_plan, upload_receipt, key_package
            )
            staged = store.record_backup_restore_preflight(
                actor, plan["plan_sha256"], synthetic_backup_restore_preflight(plan)
            )
            result = {
                "restore_plan_sha256": plan["plan_sha256"],
                "status": staged["status"],
                "network_performed": False,
                "downloaded": False,
                "decrypted": False,
                "restored": False,
                "execution_authorized": False,
            }
        elif arguments.operation == "review":
            result = review_backup_restore(
                store, Actor("iac-restore-reviewer", frozenset({"IAC"})),
                arguments.restore_plan_sha256,
            )
        elif arguments.operation == "request":
            result = request_exact_restore_approval(
                store, Actor("iac-restore-interface", frozenset({"IAC"})),
                arguments.restore_plan_sha256,
                expected_review_sha256=arguments.expected_review_sha256,
                expires_at=arguments.expires_at,
            )
        elif arguments.operation == "decide":
            result = decide_exact_restore_approval(
                store, Actor.sean(), arguments.restore_plan_sha256,
                approval_id=arguments.approval_id,
                approve=arguments.approve,
                reason=arguments.reason,
                expected_review_sha256=arguments.expected_review_sha256,
            )
        else:
            result = authorize_exact_restore_state(
                store, Actor.sean(), arguments.restore_plan_sha256,
                approval_id=arguments.approval_id,
                expected_review_sha256=arguments.expected_review_sha256,
                confirm_plan_sha256=arguments.confirm_plan_sha256,
            )
    except (
        AuthorizationError,
        BackupRestoreError,
        BackupRestoreOperatorError,
        OSError,
        ValidationError,
        ValueError,
    ):
        print(json.dumps({"ok": False, "error": "restore_operator_request_rejected"}))
        return 2
    finally:
        store.close()
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
