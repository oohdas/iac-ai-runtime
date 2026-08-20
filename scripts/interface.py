"""Local authenticated command interface. Bind externally only after production security review."""
from pathlib import Path
import argparse
import hmac
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sean_os import Actor, AuthorizationError, CommandGateway, SeanOSStore, ValidationError


MAX_BODY_BYTES=1_000_000


def require_token() -> str:
    token=os.environ.get("SEAN_OS_INTERFACE_TOKEN", "")
    if len(token) < 32:
        raise RuntimeError("SEAN_OS_INTERFACE_TOKEN must contain at least 32 characters")
    return token


def optional_operator_token(interface_token: str) -> Optional[str]:
    token=os.environ.get("SEAN_OS_OPERATOR_TOKEN", "")
    if not token:
        return None
    if len(token) < 32:
        raise RuntimeError("SEAN_OS_OPERATOR_TOKEN must contain at least 32 characters")
    if hmac.compare_digest(token, interface_token):
        raise RuntimeError("SEAN_OS_OPERATOR_TOKEN must differ from SEAN_OS_INTERFACE_TOKEN")
    return token


def handler_factory(store: SeanOSStore, token: str, operator_token: Optional[str] = None):
    gateway=CommandGateway(store, Actor("chatgpt-interface", frozenset({"IAC"})))
    operator_gateway=CommandGateway(
        store, Actor("sean-chatgpt-operator", frozenset({"IAC"}), is_sean=True)
    )

    class Handler(BaseHTTPRequestHandler):
        server_version="SeanOSInterface/0.1"

        def log_message(self, format, *args):
            # Avoid request/body/token leakage; operators use structured runtime audit records.
            return

        def _json(self, status: int, payload: dict):
            body=json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers(); self.wfile.write(body)

        def _authorized(self) -> bool:
            supplied=self.headers.get("Authorization", "")
            expected=f"Bearer {token}"
            return hmac.compare_digest(supplied, expected)

        def _operator_authorized(self) -> bool:
            if operator_token is None:
                return False
            supplied=self.headers.get("Authorization", "")
            return hmac.compare_digest(supplied, f"Bearer {operator_token}")

        def _auth_or_reject(self) -> bool:
            if self._authorized(): return True
            store.record_policy_decision(
                Actor("unauthenticated-interface", frozenset()), None, False,
                "Interface authentication failed", {"path":self.path},
            )
            self._json(401, {"error":"unauthorized"}); return False

        def _operator_auth_or_reject(self, affected_id: Optional[str] = None) -> bool:
            if self._operator_authorized(): return True
            store.record_policy_decision(
                Actor("unauthenticated-interface", frozenset()), affected_id, False,
                "Operator authentication failed", {"path":self.path},
            )
            self._json(403, {"error":"operator_authorization_required"}); return False

        def _request_json(self) -> dict:
            length=int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY_BYTES:
                raise ValidationError("Request body size is invalid")
            value=json.loads(self.rfile.read(length))
            if not isinstance(value, dict):
                raise ValidationError("Request body must be a JSON object")
            return value

        def do_GET(self):
            if not self._auth_or_reject(): return
            parsed=urlparse(self.path)
            if parsed.path == "/health":
                self._json(200, {"interface":"healthy", "runtime":store.runtime_health()}); return
            parts=parsed.path.strip("/").split("/")
            if len(parts) == 3 and parts[:2] == ["v1","records"]:
                try:
                    self._json(200, {"record":gateway.get_record(parts[2])})
                except (KeyError, AuthorizationError):
                    self._json(404, {"error":"not_found"})
                return
            if parts == ["v1","records"]:
                query=parse_qs(parsed.query)
                entity_type=query.get("entity_type", [None])[0]
                try:
                    self._json(200, {"records":gateway.list_records(entity_type)})
                except ValidationError as exc:
                    self._json(400, {"error":"invalid_request", "message":str(exc)})
                return
            if parts == ["v1","audit"]:
                query=parse_qs(parsed.query)
                try:
                    limit=int(query.get("limit", ["100"])[0])
                    self._json(200, {"events":gateway.audit_trace(limit=limit)})
                except (ValidationError, ValueError) as exc:
                    self._json(400, {"error":"invalid_request", "message":str(exc)})
                return
            if parts == ["v1","incidents"]:
                self._json(200, {"incidents":gateway.active_incidents()}); return
            if parts == ["v1","deliveries"]:
                query=parse_qs(parsed.query)
                try:
                    self._json(200, {"deliveries":gateway.deliveries(
                        status=query.get("status", [None])[0]
                    )})
                except ValidationError as exc:
                    self._json(400, {"error":"invalid_request", "message":str(exc)})
                return
            if parts == ["v1","delivery-diagnostics"]:
                self._json(200, {"diagnostics":gateway.delivery_diagnostics()}); return
            if len(parts) == 4 and parts[:2] == ["v1","commands"] and parts[3] in {"status","result"}:
                work_id=parts[2]
                try:
                    if parts[3] == "status":
                        value={"work_id":work_id, "status":gateway.status(work_id)}
                    else:
                        value={"work_id":work_id, "result":gateway.result(work_id)}
                    store.record_policy_decision(
                        Actor("chatgpt-interface", frozenset({"IAC"})), work_id, True,
                        "Authorized interface command read", {"view":parts[3]},
                    )
                    self._json(200, value)
                except AuthorizationError:
                    self._json(404, {"error":"not_found"})
                return
            self._json(404, {"error":"not_found"})

        def do_POST(self):
            parts=urlparse(self.path).path.strip("/").split("/")
            if len(parts) == 4 and parts[:2] == ["v1","incidents"] and parts[3] == "resolve":
                if not self._operator_auth_or_reject(parts[2]): return
                try:
                    request=self._request_json()
                    if set(request) != {"reason"} or not isinstance(request["reason"], str):
                        raise ValidationError("Resolution request fields are invalid")
                    incident=operator_gateway.resolve_incident(parts[2], reason=request["reason"])
                    self._json(200, {"incident":incident})
                except (ValidationError, AuthorizationError, ValueError, TypeError,
                        json.JSONDecodeError) as exc:
                    self._json(400, {"error":"invalid_request", "message":str(exc)})
                return
            if (len(parts) == 4 and parts[:2] == ["v1","deliveries"] and
                    parts[3] in {"decision", "authorize", "reset"}):
                if not self._operator_auth_or_reject(parts[2]): return
                try:
                    request=self._request_json()
                    if parts[3] == "decision":
                        if (set(request) != {"approval_id","approve","reason"} or
                                not isinstance(request["approval_id"], str) or
                                not isinstance(request["approve"], bool) or
                                not isinstance(request["reason"], str)):
                            raise ValidationError("Approval decision fields are invalid")
                        status=operator_gateway.decide_delivery_approval(
                            parts[2], approval_id=request["approval_id"],
                            approve=request["approve"], reason=request["reason"],
                        )
                        self._json(200, {"approval_id":request["approval_id"], "status":status})
                    elif parts[3] == "authorize":
                        if set(request) != {"approval_id"} or not isinstance(request["approval_id"], str):
                            raise ValidationError("Delivery authorization fields are invalid")
                        delivery=operator_gateway.authorize_delivery(
                            parts[2], approval_id=request["approval_id"]
                        )
                        self._json(200, {"delivery":delivery})
                    else:
                        if set(request) != {"reason"} or not isinstance(request["reason"], str):
                            raise ValidationError("Delivery reset fields are invalid")
                        delivery=operator_gateway.reset_failed_delivery(
                            parts[2], reason=request["reason"]
                        )
                        self._json(200, {"delivery":delivery})
                except (ValidationError, AuthorizationError, ValueError, TypeError,
                        json.JSONDecodeError) as exc:
                    self._json(400, {"error":"invalid_request", "message":str(exc)})
                return
            if not self._auth_or_reject(): return
            if parts == ["v1","deliveries","stage"]:
                try:
                    request=self._request_json()
                    if set(request) != {"plan_id"} or not isinstance(request["plan_id"], str):
                        raise ValidationError("Delivery staging fields are invalid")
                    self._json(201, {"delivery":gateway.stage_delivery(request["plan_id"])})
                except (ValidationError, AuthorizationError, ValueError, TypeError,
                        json.JSONDecodeError) as exc:
                    self._json(400, {"error":"invalid_request", "message":str(exc)})
                return
            if (len(parts) == 4 and parts[:2] == ["v1","deliveries"] and
                    parts[3] == "request-approval"):
                try:
                    request=self._request_json()
                    if (set(request) != {"max_impact","expires_at"} or
                            not all(isinstance(request[key], str) for key in request)):
                        raise ValidationError("Approval request fields are invalid")
                    approval_id=gateway.request_delivery_approval(
                        parts[2], max_impact=request["max_impact"],
                        expires_at=request["expires_at"],
                    )
                    self._json(201, {"approval_id":approval_id, "status":"PENDING"})
                except (ValidationError, AuthorizationError, ValueError, TypeError,
                        json.JSONDecodeError) as exc:
                    self._json(400, {"error":"invalid_request", "message":str(exc)})
                return
            if self.path != "/v1/commands":
                self._json(404, {"error":"not_found"}); return
            try:
                request=self._request_json()
                if set(request) != {"request_id","command_type","payload"}:
                    raise ValidationError("Request envelope fields are invalid")
                result=gateway.submit(
                    str(request["request_id"]), str(request["command_type"]), request["payload"]
                )
                self._json(202, result)
            except (ValidationError, AuthorizationError, ValueError, TypeError, json.JSONDecodeError) as exc:
                self._json(400, {"error":"invalid_request", "message":str(exc)})

    return Handler


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--database", default="sean-os-local.db")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args=parser.parse_args(); token=require_token()
    operator_token=optional_operator_token(token)
    store=SeanOSStore(args.database, scope_profile="IAC")
    server=HTTPServer((args.host, args.port), handler_factory(store, token, operator_token))
    try:
        server.serve_forever()
    finally:
        server.server_close(); store.close()


if __name__ == "__main__":
    main()
