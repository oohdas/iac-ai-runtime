import json
from io import BytesIO
import unittest

from scripts.interface import handler_factory
from sean_os import Actor, EscalationRoute, SeanOSStore, plan_alert_deliveries


class InterfaceHTTPTests(unittest.TestCase):
    interface_token="synthetic-interface-token-that-is-long-enough"
    operator_token="synthetic-operator-token-that-is-different"

    def setUp(self):
        self.store=SeanOSStore(":memory:", scope_profile="IAC")
        plan=plan_alert_deliveries(
            [{"code":"NO_ACTIVE_WORKER", "severity":"CRITICAL", "summary":"none"}],
            route=EscalationRoute("iac-operator", "IAC", "EMAIL", "iac-ops-alias"),
            owner_scope="IAC",
        )[0]
        self.store.record_alert_observation(Actor("monitor", frozenset({"IAC"})), plan)
        self.plan_id=plan["plan_id"]
        self.handler=handler_factory(self.store, self.interface_token, self.operator_token)

    def tearDown(self):
        self.store.close()

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


if __name__ == "__main__":
    unittest.main()
