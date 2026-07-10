"""
Sensitive File Access detection rule.

Detects access to files commonly read during credential dumping, lateral
movement, or reconnaissance on Linux systems.

Sigma rule references:
  https://github.com/SigmaHQ/sigma/blob/master/rules/linux/file_access/file_access_lin_susp_shadow_access.yml
  https://github.com/SigmaHQ/sigma/blob/master/rules/linux/file_access/file_access_lin_etc_passwd_access.yml
MITRE ATT&CK: T1003.008 — OS Credential Dumping: /etc/passwd and /etc/shadow
              T1552.004 — Unsecured Credentials: Private Keys
Tactic: TA0006 — Credential Access
"""

from datetime import datetime
from typing import Any, Dict, List

from src.models import Alert, Evidence, SecurityEvent, make_fingerprint
from src.rules.base import Rule

# Checked as case-insensitive substrings against event.resource.
_DEFAULT_SENSITIVE_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/.ssh/",
    "/root/",
    "authorized_keys",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    ".bash_history",
    "/var/log/auth",
    "/var/log/secure",
    "/proc/",
]


class SensitiveFileAccessRule(Rule):
    name = "sensitive_file_access"
    severity = "high"
    mitre_technique = "T1003.008"
    mitre_tactic = "TA0006"

    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        raw_paths = config.get("sensitive_paths", _DEFAULT_SENSITIVE_PATHS)
        # Normalize to lowercase once at construction time for fast matching.
        self._sensitive_paths: List[str] = [p.lower() for p in raw_paths]

    def _is_sensitive(self, resource: str) -> bool:
        resource_lower = (resource or "").lower()
        return any(path in resource_lower for path in self._sensitive_paths)

    def matches(
        self, event: SecurityEvent, recent_events: List[SecurityEvent]
    ) -> bool:
        if event.event_type != "file_access":
            return False
        return self._is_sensitive(event.resource or "")

    def build_alert(
        self, event: SecurityEvent, recent_events: List[SecurityEvent]
    ) -> Alert:
        target_user = event.user or "unknown"
        resource = event.resource or "unknown"

        # Include any other sensitive file accesses in the recent window as evidence.
        related_hits = [
            e for e in recent_events
            if e.event_type == "file_access" and self._is_sensitive(e.resource or "")
        ]
        all_hits = related_hits + [event]
        all_hits.sort(key=lambda e: e.timestamp)

        evidence = [
            Evidence(
                event=f"File access by '{e.user or 'unknown'}' to '{e.resource}' on {e.source}",
                timestamp=e.timestamp,
                raw_log=e.raw_log,
            )
            for e in all_hits
        ]

        return Alert(
            timestamp=datetime.utcnow(),
            type="sensitive_file_access",
            severity=self.severity,
            description=(
                f"Sensitive file accessed: '{resource}' by user '{target_user}' "
                f"on {event.source}."
            ),
            evidence=evidence,
            ai_reasoning=(
                f"Deterministic rule '{self.name}' fired. "
                f"Resource '{resource}' matched a sensitive path pattern. "
                f"MITRE {self.mitre_technique} ({self.mitre_tactic})."
            ),
            confidence=1.0,
            recommended_actions=[
                f"Review why user '{target_user}' accessed '{resource}'.",
                "Check for credential dumping tools (e.g. unshadow, john, hashcat).",
                "Inspect shell history and running processes on the affected system.",
                "Rotate credentials if /etc/shadow or SSH private keys were accessed.",
            ],
            fingerprint=make_fingerprint(
                "sensitive_file_access", event.user or "", event.source
            ),
        )
