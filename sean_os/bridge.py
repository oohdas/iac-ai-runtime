from __future__ import annotations

import hashlib
import json
from typing import Any

from .commands import CommandGateway
from .security import secret_findings
from .store import Actor, AuthorizationError, SeanOSStore


class BridgeDenied(AuthorizationError):
    pass


class IACBridgeReceiver:
    """Fail-closed receiver for commands from the separately owned Sean OS."""

    VERSION = "sean-os-iac-bridge/v1"
    ALLOWED_COMMANDS = {
        "CREATE_IAC_GOAL", "CREATE_PROJECT", "REVIEW_PORTFOLIO",
        "QUALIFY_REVENUE", "COMPARE_REVENUE_PORTFOLIO", "GENERATE_REPORT",
        "REQUEST_CUSTOMER_CONTACT_APPROVAL",
    }
    PERSONAL_KEYS = {
        "personal", "family", "health", "medical", "bank", "rbc", "wealth",
        "home_address",
    }

    def __init__(self, store: SeanOSStore):
        self.gateway = CommandGateway(
            store, Actor("sean-os-bridge", frozenset({"IAC"}))
        )

    def accept(self, envelope: dict[str, Any]) -> dict[str, str]:
        required = {
            "contract_version", "request_id", "issued_at", "target", "command_type",
            "payload", "personal_data_included", "payload_sha256",
        }
        if set(envelope) != required:
            raise BridgeDenied("Bridge envelope fields do not match the contract")
        if envelope["contract_version"] != self.VERSION or envelope["target"] != "IAC":
            raise BridgeDenied("Bridge version or target mismatch")
        if envelope["personal_data_included"] is not False:
            raise BridgeDenied("PERSONAL data is prohibited on the IAC bridge")
        command = str(envelope["command_type"]).upper()
        payload = envelope["payload"]
        if command not in self.ALLOWED_COMMANDS or not isinstance(payload, dict):
            raise BridgeDenied("Command is not exposed across the ownership bridge")
        if self._personal_paths(payload) or secret_findings(payload):
            raise BridgeDenied("Bridge payload contains prohibited PERSONAL or secret material")
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if envelope["payload_sha256"] != expected:
            raise BridgeDenied("Bridge command integrity check failed")
        submitted = self.gateway.submit(
            f"bridge:{envelope['request_id']}", command, payload, scope="IAC"
        )
        return {
            "contract_version": self.VERSION,
            "request_id": str(envelope["request_id"]),
            "iac_work_id": submitted["work_id"],
            "status": submitted["status"],
        }

    def _personal_paths(self, value: Any, path: str = "$") -> list[str]:
        findings: list[str] = []
        if isinstance(value, dict):
            for key, item in value.items():
                normalized = str(key).strip().lower().replace("-", "_").replace(" ", "_")
                child = f"{path}.{key}"
                if normalized in self.PERSONAL_KEYS:
                    findings.append(child)
                findings.extend(self._personal_paths(item, child))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                findings.extend(self._personal_paths(item, f"{path}[{index}]"))
        return findings
