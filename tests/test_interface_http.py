import json
from io import BytesIO
import tempfile
import unittest
from pathlib import Path

from scripts.interface import handler_factory
from sean_os import (
    Actor,
    EscalationRoute,
    SeanOSStore,
    build_backup_transfer_plan,
    build_independent_backup_approval_package,
    plan_alert_deliveries,
    synthetic_backup_adapter_receipt,
)


class InterfaceHTTPTests(unittest.TestCase):
    interface_token="synthetic-interface-token-that-is-long-enough"
    operator_token="synthetic-operator-token-that-is-different"

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.store=SeanOSStore(Path(self.temp.name) / "interface.db", scope_profile="IAC")
        plan=plan_alert_deliveries(
            [{"code":"NO_ACTIVE_WORKER", "severity":"CRITICAL", "summary":"none"}],
            route=EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias"),
            owner_scope="IAC",
        )[0]
        self.store.record_alert_observation(Actor("monitor", frozenset({"IAC"})), plan)
        self.plan_id=plan["plan_id"]
        self.handler=handler_factory(self.store, self.interface_token, self.operator_token)

    def tearDown(self):
        self.store.close(); self.temp.cleanup()

    def request(self, method, path, token, body=None):
        payload=b"" if body is None else json.dumps(body).encode("utf-8")
        raw=(
            f"{method} {path} HTTP/1.1\r\nHost: localhost\r\n"
            f"Authorization: Bearer {token}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n\r\n"
        ).encode("ascii") + payload

        class NonClosingBytesIO(BytesIO):
            def close(self):
                pass

        class InMemorySocket:
            def __init__(self, request_bytes):
                self.input=BytesIO(request_bytes); self.output=NonClosingBytesIO()

            def makefile(self, mode, buffering=None):
                return self.input if "r" in mode else self.output

            def sendall(self, data):
                self.output.write(data)

            def close(self):
                pass

        transport=InMemorySocket(raw)
        self.handler(transport, ("127.0.0.1", 1), object())
        headers, payload=transport.output.getvalue().split(b"\r\n\r\n", 1)
        status=int(headers.split(b"\r\n", 1)[0].split()[1])
        return status, json.loads(payload)

    def test_delivery_review_and_operator_approval_flow(self):
        status, body=self.request(
            "POST", "/v1/deliveries/stage", self.interface_token,
            {"plan_id":self.plan_id},
        )
        self.assertEqual(status, 201)
        delivery_id=body["delivery"]["delivery_id"]

        status, body=self.request(
            "POST", f"/v1/deliveries/{delivery_id}/request-approval",
            self.interface_token,
            {"max_impact":"one synthetic alert", "expires_at":"2099-01-01T00:00:00+00:00"},
        )
        self.assertEqual(status, 201)
        approval_id=body["approval_id"]

        status, body=self.request(
            "POST", f"/v1/deliveries/{delivery_id}/decision", self.interface_token,
            {"approval_id":approval_id, "approve":True, "reason":"Synthetic route reviewed"},
        )
        self.assertEqual((status, body["error"]), (403, "operator_authorization_required"))

        status, body=self.request(
            "POST", f"/v1/deliveries/{delivery_id}/decision", self.operator_token,
            {"approval_id":approval_id, "approve":True, "reason":"Synthetic route reviewed"},
        )
        self.assertEqual((status, body["status"]), (200, "APPROVED"))

        status, body=self.request(
            "POST", f"/v1/deliveries/{delivery_id}/authorize", self.operator_token,
            {"approval_id":approval_id},
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["delivery"]["status"], "AUTHORIZED")

        status, body=self.request(
            "GET", "/v1/deliveries?status=AUTHORIZED", self.interface_token
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["deliveries"][0]["delivery_id"], delivery_id)

        self.store.connection.execute(
            """UPDATE alert_delivery_outbox SET status='FAILED', attempt_count=3,
               last_error='Synthetic adapter fault' WHERE delivery_id=?""",
            (delivery_id,),
        )
        self.store.connection.commit()
        status, body=self.request(
            "GET", "/v1/delivery-diagnostics", self.interface_token
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["diagnostics"]["failed"], 1)
        self.assertFalse(body["diagnostics"]["manual_execution_authorized"])

        status, body=self.request(
            "POST", f"/v1/deliveries/{delivery_id}/reset", self.interface_token,
            {"reason":"Synthetic failure reviewed"},
        )
        self.assertEqual((status, body["error"]), (403, "operator_authorization_required"))
        status, body=self.request(
            "POST", f"/v1/deliveries/{delivery_id}/reset", self.operator_token,
            {"reason":"Synthetic failure reviewed"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["delivery"]["status"], "STAGED")
        self.assertIsNone(body["delivery"]["approval_id"])

    def test_invalid_request_does_not_reflect_secret_like_input(self):
        synthetic_secret="sk-" + "i" * 24
        status, body=self.request(
            "GET", f"/v1/audit?limit={synthetic_secret}", self.interface_token
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["message"], "Request rejected")
        self.assertNotIn(synthetic_secret, json.dumps(body, sort_keys=True))

    def test_authentication_audit_drops_query_string(self):
        synthetic_secret="sk-" + "j" * 24
        status, _body=self.request(
            "GET", f"/v1/records?password={synthetic_secret}", "wrong-token"
        )
        self.assertEqual(status, 401)
        event=self.store.audit_events()[-1]
        self.assertEqual(event["details"]["path"], "/v1/records")
        self.assertNotIn(synthetic_secret, json.dumps(event, sort_keys=True))

    def test_backup_review_and_operator_exact_approval_flow(self):
        proposal={
            "format":"sean-os-independent-backup-drill-proposal/v2",
            "owner_scope":"IAC",
            "project_id":"synthetic-project",
            "environment_id":"synthetic-environment",
            "service_id":"synthetic-service",
            "primary_volume_id":"synthetic-primary-volume",
            "destination_kind":"ENCRYPTED_OBJECT_STORAGE",
            "destination_provider":"BACKBLAZE_B2",
            "destination_ref":"synthetic-backup-vault:object-001",
            "data_region":"CA_EAST",
            "independent_from_primary":True,
            "encryption_at_rest":True,
            "encryption_key_owner":"IAC",
            "access_owner":"IAC",
            "retention_days":30,
            "object_lock_enabled":True,
            "restore_target_ref":"synthetic-isolated-restore:001",
            "isolated_restore":True,
            "overwrite_production":False,
            "operator":"sean",
            "rollback_owner":"sean",
            "window_start":"2030-01-02T09:00:00-05:00",
            "window_end":"2030-01-02T11:00:00-05:00",
            "max_cost_cad":10,
            "kill_switch_change_requested":True,
            "live_connectors_enabled":False,
            "real_data_authorized":False,
        }
        package=build_independent_backup_approval_package(proposal)
        manifest=self.store.backup_manifest(
            Actor.sean(), Path(self.temp.name) / "interface-backup.db"
        )
        plan=build_backup_transfer_plan(
            package,
            manifest,
            object_ref="backups/interface-synthetic.db.enc",
            provider_endpoint="s3.ca-east-006.backblazeb2.com",
            writer_identity_ref="iac-vault-writer:backup-only-v1",
            client_encryption_key_ref="iac-keyring:backup-key-v1",
        )
        self.store.stage_backup_transfer(Actor.sean(), plan, package)
        self.store.record_backup_transfer_preflight(
            Actor.sean(), plan["plan_sha256"],
            synthetic_backup_adapter_receipt(plan, package),
        )

        status, body=self.request(
            "GET", "/v1/backup-transfers?status=PREFLIGHT_VALIDATED",
            self.interface_token,
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["transfers"][0]["plan_sha256"], plan["plan_sha256"])

        status, body=self.request(
            "POST", f"/v1/backup-transfers/{plan['plan_sha256']}/request-approval",
            self.interface_token,
            {"max_impact":"One synthetic backup; CAD 10 maximum",
             "expires_at":"2099-01-01T00:00:00+00:00"},
        )
        self.assertEqual(status, 201)
        approval_id=body["approval_id"]

        status, body=self.request(
            "POST", f"/v1/backup-transfers/{plan['plan_sha256']}/decision",
            self.interface_token,
            {"approval_id":approval_id, "approve":True, "reason":"Synthetic reviewed"},
        )
        self.assertEqual((status, body["error"]), (403, "operator_authorization_required"))
        status, body=self.request(
            "POST", f"/v1/backup-transfers/{plan['plan_sha256']}/decision",
            self.operator_token,
            {"approval_id":approval_id, "approve":True, "reason":"Synthetic reviewed"},
        )
        self.assertEqual((status, body["status"]), (200, "APPROVED"))
        status, body=self.request(
            "POST", f"/v1/backup-transfers/{plan['plan_sha256']}/authorize",
            self.operator_token,
            {"approval_id":approval_id},
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["transfer"]["status"], "AUTHORIZED")
        self.assertFalse(body["transfer"]["plan_payload"]["network_enabled"])
        self.assertFalse(body["transfer"]["plan_payload"]["execution_authorized"])


if __name__ == "__main__":
    unittest.main()
