import hashlib
import json
import unittest

from sean_os import BridgeDenied, IACBridgeReceiver, SeanOSStore


def envelope(command="CREATE_IAC_GOAL", payload=None, request_id="request-1"):
    payload = payload or {"name": "Exit readiness", "success_metric": "transferability"}
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "contract_version": "sean-os-iac-bridge/v1",
        "request_id": request_id,
        "issued_at": "2030-01-01T00:00:00+00:00",
        "target": "IAC",
        "command_type": command,
        "payload": payload,
        "personal_data_included": False,
        "payload_sha256": digest,
    }


class IACBridgeReceiverTests(unittest.TestCase):
    def setUp(self):
        self.store = SeanOSStore(scope_profile="IAC")
        self.receiver = IACBridgeReceiver(self.store)

    def tearDown(self):
        self.store.close()

    def test_valid_command_is_queued_and_receipt_has_no_payload(self):
        receipt = self.receiver.accept(envelope())
        self.assertEqual(receipt["status"], "QUEUED")
        self.assertEqual(set(receipt), {
            "contract_version", "request_id", "iac_work_id", "status"
        })

    def test_replay_is_idempotent(self):
        first = self.receiver.accept(envelope())
        second = self.receiver.accept(envelope())
        self.assertEqual(first["iac_work_id"], second["iac_work_id"])

    def test_tampering_and_personal_material_fail_closed(self):
        altered = envelope()
        altered["payload_sha256"] = "0" * 64
        with self.assertRaises(BridgeDenied):
            self.receiver.accept(altered)
        with self.assertRaises(BridgeDenied):
            self.receiver.accept(envelope(payload={"health": "private"}))

    def test_arbitrary_actions_and_extra_envelope_fields_fail_closed(self):
        with self.assertRaises(BridgeDenied):
            self.receiver.accept(envelope(command="SEND_EMAIL", payload={"to": "x"}))
        extra = envelope()
        extra["override"] = True
        with self.assertRaises(BridgeDenied):
            self.receiver.accept(extra)


if __name__ == "__main__":
    unittest.main()
