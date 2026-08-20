from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .store import Actor, AuthorizationError, SeanOSStore


class PolicyDenied(AuthorizationError):
    def __init__(self, reason: str, *, approval_required: bool = False):
        super().__init__(reason)
        self.reason = reason
        self.approval_required = approval_required


@dataclass(frozen=True)
class ActionPolicy:
    name: str
    allowed_scopes: frozenset[str]
    external_effect: bool
    reversible: bool
    approval_required: bool
    cost_bearing: bool
    prohibited: bool = False


Handler = Callable[[dict[str, Any]], dict[str, Any]]


class ActionRegistry:
    def __init__(self) -> None:
        self._entries: dict[str, tuple[ActionPolicy, Handler]] = {}

    def register(self, policy: ActionPolicy, handler: Handler) -> None:
        if policy.name in self._entries:
            raise ValueError(f"Action already registered: {policy.name}")
        self._entries[policy.name] = (policy, handler)

    def policy_for(self, task_type: str) -> ActionPolicy:
        entry = self._entries.get(task_type)
        if entry is None:
            raise PolicyDenied(f"No registered action policy or handler for {task_type}")
        return entry[0]

    def execute(self, store: SeanOSStore, actor: Actor, work: dict[str, Any]) -> dict[str, Any]:
        work_id = work.get("id")
        task_type = work.get("task_type", "<missing>")
        if work_id:
            replay=store.completed_action_result(work_id, task_type)
            if replay is not None:
                store.record_policy_decision(
                    actor, work_id, True, "Returning durable result; handler replay suppressed",
                    {"task_type":task_type},
                )
                return replay
        try:
            if store.kill_switch_enabled():
                raise PolicyDenied("Kill switch is ON; execution denied")
            policy = self.policy_for(task_type)
            payload = work["payload"]
            if policy.prohibited:
                raise PolicyDenied(f"Action {policy.name} is prohibited")
            if work["owner_scope"] not in policy.allowed_scopes:
                raise PolicyDenied(
                    f"Action {policy.name} is not permitted in {work['owner_scope']} scope"
                )
            estimated = float(payload.get("estimated_cost_units", 0))
            if estimated > 0 and not policy.cost_bearing:
                raise PolicyDenied(f"Non-cost-bearing action {policy.name} declared a cost")
            if policy.cost_bearing and estimated <= 0:
                raise PolicyDenied(f"Cost-bearing action {policy.name} requires a positive estimate")
            if policy.external_effect and not policy.approval_required:
                raise PolicyDenied(f"External action {policy.name} must require approval")
            if not policy.reversible and not policy.approval_required:
                raise PolicyDenied(f"Irreversible action {policy.name} must require approval")
            if policy.approval_required:
                approval_id = payload.get("approval_id")
                target = payload.get("action_target")
                if not approval_id or not target:
                    raise PolicyDenied(
                        f"Action {policy.name} requires an exact approval and target",
                        approval_required=True,
                    )
                try:
                    store.consume_approval(
                        actor, approval_id, action_type=policy.name, target=target
                    )
                except AuthorizationError as exc:
                    raise PolicyDenied(str(exc), approval_required=True) from exc
        except PolicyDenied as exc:
            store.record_policy_decision(
                actor, work_id, False, exc.reason,
                {"task_type": task_type, "tool":"policy_registry",
                 "rollback_status":"NOT_STARTED", "outcome":"DENIED"}
            )
            raise
        evidence=[{"field":key, "record_id":value} for key, value in payload.items()
                  if key.endswith("_id") and isinstance(value, str)]
        store.record_policy_decision(
            actor, work_id, True, "Registered action policy satisfied",
            {"task_type": policy.name, "tool":"registered_handler",
             "cost_units":estimated, "evidence":evidence,
             "rollback_status":"AVAILABLE" if policy.reversible else "NOT_AVAILABLE",
             "outcome":"AUTHORIZED"},
        )
        result=self._entries[policy.name][1](payload)
        if work_id:
            store.record_action_result(actor, work_id, policy.name, result)
        return result


def default_registry() -> ActionRegistry:
    registry = ActionRegistry()
    registry.register(
        ActionPolicy(
            name="NOOP", allowed_scopes=frozenset({"PERSONAL", "IAC", "SHARED"}),
            external_effect=False, reversible=True, approval_required=False,
            cost_bearing=False,
        ),
        lambda payload: {"ok": True, "echo": payload},
    )
    return registry
