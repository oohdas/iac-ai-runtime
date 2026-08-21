from __future__ import annotations

import re
from typing import Any


SENSITIVE_KEYS={
    "password", "passphrase", "secret", "client_secret", "api_key", "access_token",
    "refresh_token", "recovery_code", "recovery_codes", "private_key", "account_number",
    "routing_number", "credential", "credentials",
}
SECRET_PATTERNS=(
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("openai_style_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[A-Z0-9]{16}\b")),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{20,}={0,2}\b", re.I)),
)


def safe_persisted_text(
    value: Any, *, fallback: str = "Sensitive detail redacted", max_length: int = 500,
) -> str:
    """Return bounded single-line text that is safe for durable operational evidence."""
    text=" ".join(str(value).split()).strip()
    if not text or secret_findings(text):
        return fallback
    return text[:max_length]


def safe_exception_summary(error: BaseException, *, context: str) -> str:
    """Describe an unexpected exception without persisting its potentially sensitive message."""
    return safe_persisted_text(
        f"{type(error).__name__}: {context}", fallback="Runtime operation failed"
    )


def secret_findings(value: Any, path: str = "$") -> list[dict[str, str]]:
    """Return secret classifications and paths, never secret values."""
    findings=[]
    if isinstance(value, dict):
        for key, item in value.items():
            normalized=str(key).strip().lower().replace("-", "_").replace(" ", "_")
            child=f"{path}.{key}"
            if normalized in SENSITIVE_KEYS:
                findings.append({"path":child, "type":"sensitive_key"})
            findings.extend(secret_findings(item, child))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            findings.extend(secret_findings(item, f"{path}[{index}]"))
    elif isinstance(value, str):
        for kind, pattern in SECRET_PATTERNS:
            if pattern.search(value):
                findings.append({"path":path, "type":kind})
    return findings
