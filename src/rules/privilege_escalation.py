"""
Privilege Escalation After Login detection rule.

Detects a privilege change (sudo, su, setuid execution) that occurs shortly
after a successful login on the same source system — the classic CTF attack
sequence of: brute force SSH → successful login → escalate to root.

Sigma rule reference:
  https://github.com/SigmaHQ/sigma/blob/master/rules/linux/builtin/auth/lnx_auth_priv_esc_via_sudo.yml
MITRE ATT&CK: T1548 — Abuse Elevation Control Mechanism
Tactic: TA0004 — Privilege Escalation

Note: For this rule to receive login_attempt events as context, the
correlation_rules.py get_related_event_types() for privilege_change must
include 'login_attempt'. This is updated alongside this rule.
"""

from datetime import datetime
from typing import Any, Dict, List

from src.models import Alert, Evidence, SecurityEvent, make_fingerprint
from src.rules.base import Rule

_DEFAULT_WINDOW_SECONDS = 300


class PrivilegeEscalationRule(Rule):
    name = "privilege_escalation_after_login"
    severity = "critical"
    mitre_technique = "T1548"
    mitre_tactic = "TA0004"

    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        self.window_seconds: int = config.get("window_seconds", _DEFAULT_WINDOW_SECONDS)

    def _recent_successful_logins(
        self, recent_events: List[SecurityEvent]
    ) -> List[SecurityEvent]:
        return [
            e for e in recent_events
            if e.event_type == "login_attempt" and e.action == "succeeded"
        ]

    def matches(
        self, event: SecurityEvent, recent_events: List[SecurityEvent]
    ) -> bool:
        if event.event_type != "privilege_change":
            return False
        return len(self._recent_successful_logins(recent_events)) > 0

    def build_alert(
        self, event: SecurityEvent, recent_events: List[SecurityEvent]
    ) -> Alert:
        target_user = event.user or "unknown"
        resource = event.resource or "unknown"
        prior_logins = self._recent_successful_logins(recent_events)

        all_events = sorted(prior_logins + [event], key=lambda e: e.timestamp)

        evidence = []
        for e in all_events:
            if e.event_type == "login_attempt":
                ip = (e.details or {}).get("ip")
                desc = (
                    f"Successful login for user '{e.user or 'unknown'}' on {e.source}"
                    + (f" from IP {ip}" if ip else "")
                )
            else:
                desc = (
                    f"Privilege change by '{e.user or 'unknown'}' on {e.source} "
                    f"targeting '{e.resource or 'unknown'}'"
                )
            evidence.append(Evidence(event=desc, timestamp=e.timestamp, raw_log=e.raw_log))

        return Alert(
            timestamp=datetime.utcnow(),
            type="privilege_escalation_after_login",
            severity=self.severity,
            description=(
                f"Privilege escalation after login: user '{target_user}' performed "
                f"a privilege change to '{resource}' on {event.source} within "
                f"{self.window_seconds} seconds of a successful login."
            ),
            evidence=evidence,
            ai_reasoning=(
                f"Deterministic rule '{self.name}' fired. "
                f"A privilege_change event followed {len(prior_logins)} successful "
                f"login(s) within {self.window_seconds}s on the same system. "
                f"MITRE {self.mitre_technique} ({self.mitre_tactic})."
            ),
            confidence=0.9,
            recommended_actions=[
                f"Verify that user '{target_user}' is authorized to escalate privileges on '{event.source}'.",
                "Review sudo/su logs and the commands run after escalation.",
                "Check for new cron jobs, SUID binaries, or persistence mechanisms.",
                "If unexpected, revoke access and begin incident response.",
            ],
            fingerprint=make_fingerprint(
                "privilege_escalation_after_login", event.user or "", event.source
            ),
        )
