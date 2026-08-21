#!/usr/bin/env python3
"""Review and change exact synthetic-backup approval state without network use."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sean_os import (
    Actor,
    AuthorizationError,
    BackupActivationError,
    BackupAdapterError,
    SeanOSStore,
    ValidationError,
)
from sean_os.backup_operator import (
    BackupOperatorError,
    authorize_exact_backup_state,
    decide_exact_backup_approval,
    request_exact_backup_approval,
    review_backup_transfer,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Hash-bound state-only operator workflow for a synthetic IAC backup"
    )
    subparsers = parser.add_subparsers(dest="operation", required=True)

    def common(name: str) -> argparse.ArgumentParser:
        command = subparsers.add_parser(name)
        command.add_argument("database", type=Path)
        command.add_argument("plan_sha256")
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
        if arguments.operation == "review":
            result = review_backup_transfer(
                store, Actor("iac-backup-reviewer", frozenset({"IAC"})),
                arguments.plan_sha256,
            )
        elif arguments.operation == "request":
            result = request_exact_backup_approval(
                store, Actor("iac-backup-interface", frozenset({"IAC"})),
                arguments.plan_sha256,
                expected_review_sha256=arguments.expected_review_sha256,
                expires_at=arguments.expires_at,
            )
        elif arguments.operation == "decide":
            result = decide_exact_backup_approval(
                store, Actor.sean(), arguments.plan_sha256,
                approval_id=arguments.approval_id,
                approve=arguments.approve,
                reason=arguments.reason,
                expected_review_sha256=arguments.expected_review_sha256,
            )
        else:
            result = authorize_exact_backup_state(
                store, Actor.sean(), arguments.plan_sha256,
                approval_id=arguments.approval_id,
                expected_review_sha256=arguments.expected_review_sha256,
                confirm_plan_sha256=arguments.confirm_plan_sha256,
            )
    except (
        BackupActivationError,
        BackupAdapterError,
        BackupOperatorError,
        ValidationError,
        AuthorizationError,
    ):
        print(json.dumps({"ok": False, "error": "backup_operator_request_rejected"}))
        return 2
    finally:
        store.close()
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
