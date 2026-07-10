"""
SSH Brute Force detection rule.

Detects repeated failed SSH login attempts against the same user on the same
source system within a 60-second window.

Sigma rule reference (threshold-based brute force):
https://github.com/SigmaHQ/sigma/blob/master/rules/linux/builtin/auth/lnx_auth_brute_force.yml
MITRE ATT&CK: T1110.001 — Brute Force: Password Guessing
Tactic: TA0006 — Credential Access
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from src.models import Alert, Evidence, SecurityEvent, make_fingerprint
from src.rules.base import Rule

_DEFAULT_THRESHOLD = 5
_DEFAULT_WINDOW_SECONDS = 60


class SSHBruteForceRule(Rule):
    name = "ssh_brute_force"
    severity = "high"
    mitre_technique = "T1110.001"
    mitre_tactic = "TA0006"

    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        self.threshold: int = config.get("threshold", _DEFAULT_THRESHOLD)
        self.window_seconds: int = config.get("window_seconds", _DEFAULT_WINDOW_SECONDS)

    def _failed_attempts(
        self, event: SecurityEvent, recent_events: List[SecurityEvent]
    ) -> List[SecurityEvent]:
        """
        Return all failed login_attempt events in recent_events that share
        the same source IP as the triggering event (if an IP is available),
        or all failed login attempts when no IP is present.

        Note: recent_events is already filtered by (user, source) and the
        60-second lookback window set in CorrelationRule. Cross-username
        brute force from the same IP is not detected by this rule — that
        would require a separate IP-indexed query.
        """
        attacker_ip: Optional[str] = (event.details or {}).get("ip")

        failed = []
        for e in recent_events:
            if e.event_type != "login_attempt" or e.action != "failed":
                continue
            if attacker_ip:
                if (e.details or {}).get("ip") == attacker_ip:
                    failed.append(e)
            else:
                failed.append(e)
        return failed

    def matches(
        self, event: SecurityEvent, recent_events: List[SecurityEvent]
    ) -> bool:
        if event.event_type != "login_attempt" or event.action != "failed":
            return False
        # The current event counts as one; recent_events holds preceding events.
        prior_failures = self._failed_attempts(event, recent_events)
        return (len(prior_failures) + 1) >= self.threshold

    def build_alert(
        self, event: SecurityEvent, recent_events: List[SecurityEvent]
    ) -> Alert:
        prior_failures = self._failed_attempts(event, recent_events)
        all_failures = prior_failures + [event]
        all_failures.sort(key=lambda e: e.timestamp)

        attacker_ip: Optional[str] = (event.details or {}).get("ip")
        ip_clause = f" from IP {attacker_ip}" if attacker_ip else ""
        target_user = event.user or "unknown"

        evidence = [
            Evidence(
                event=(
                    f"Failed login attempt for user '{e.user}' on {e.source}"
                    + (f" from IP {(e.details or {}).get('ip')}" if (e.details or {}).get("ip") else "")
                ),
                timestamp=e.timestamp,
                raw_log=e.raw_log,
            )
            for e in all_failures
        ]

        return Alert(
            timestamp=datetime.utcnow(),
            type="ssh_brute_force",
            severity=self.severity,
            description=(
                f"SSH brute force detected: {len(all_failures)} failed login attempts "
                f"for user '{target_user}' on {event.source}{ip_clause} "
                f"within {self.window_seconds} seconds."
            ),
            evidence=evidence,
            # ai_reasoning is repurposed here to hold the rule's rationale.
            ai_reasoning=(
                f"Deterministic rule '{self.name}' fired. "
                f"Threshold: {self.threshold} failures in {self.window_seconds}s. "
                f"Observed: {len(all_failures)}. "
                f"MITRE {self.mitre_technique} ({self.mitre_tactic})."
            ),
            confidence=1.0,
            recommended_actions=[
                f"Block source IP{ip_clause} at the firewall.",
                f"Review account '{target_user}' for unauthorized access.",
                "Enable fail2ban or equivalent on the affected system.",
                "Rotate credentials for the targeted account.",
            ],
            fingerprint=make_fingerprint(
                "ssh_brute_force", event.user or "", event.source, attacker_ip or ""
            ),
        )
