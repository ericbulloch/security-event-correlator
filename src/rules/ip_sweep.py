"""
IP Sweep / Coordinated Multi-Target Attack detection rule.

Detects when the same source IP appears in events across multiple distinct
source systems within a short time window.  A single attacker hitting three or
more machines simultaneously is a strong indicator of automated, coordinated
activity — lateral movement, credential-stuffing campaigns, or broad
reconnaissance.

Unlike the per-system SSH brute force rule (which detects many failures on one
box), this rule deliberately ignores per-user/per-source boundaries and queries
ALL recent events that share the same attacker IP, regardless of which machine
logged them.

Sigma rule reference (network sweep / scanning):
https://github.com/SigmaHQ/sigma/blob/master/rules/network/net_scan_ports.yml
MITRE ATT&CK: T1018 — Remote System Discovery / T1046 — Network Service
              Discovery (multi-host variant)
Tactic: TA0007 — Discovery
"""

from datetime import datetime
from typing import Any, Dict, List

from src.models import Alert, Evidence, SecurityEvent, make_fingerprint
from src.rules.base import Rule

_DEFAULT_MIN_SOURCES = 3
_DEFAULT_WINDOW_SECONDS = 600


class IPSweepRule(Rule):
    name = "ip_sweep"
    severity = "high"
    mitre_technique = "T1018"
    mitre_tactic = "TA0007"

    # This rule needs the cross-source IP event list, not the standard
    # per-user/per-source recent_events list.
    uses_ip_context: bool = True

    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        self.min_sources: int = config.get("min_sources", _DEFAULT_MIN_SOURCES)
        self.window_seconds: int = config.get("window_seconds", _DEFAULT_WINDOW_SECONDS)

    def _attacker_ip(self, event: SecurityEvent) -> str:
        return (event.details or {}).get("ip", "")

    def _distinct_sources(self, ip_events: List[SecurityEvent]) -> List[str]:
        seen = set()
        result = []
        for e in ip_events:
            if e.source not in seen:
                seen.add(e.source)
                result.append(e.source)
        return result

    def matches(
        self, event: SecurityEvent, recent_events: List[SecurityEvent]
    ) -> bool:
        """
        `recent_events` here is ip_events — all events carrying the same
        attacker IP fetched by the worker (passed by the engine when
        uses_ip_context is True).
        """
        ip = self._attacker_ip(event)
        if not ip:
            return False

        # Count distinct sources across ip_events + the current event's source.
        all_events = recent_events + [event]
        distinct = self._distinct_sources(all_events)
        return len(distinct) >= self.min_sources

    def build_alert(
        self, event: SecurityEvent, recent_events: List[SecurityEvent]
    ) -> Alert:
        ip = self._attacker_ip(event)
        all_events = recent_events + [event]
        all_events.sort(key=lambda e: e.timestamp)

        distinct_sources = self._distinct_sources(all_events)
        source_list = ", ".join(distinct_sources)

        evidence = [
            Evidence(
                event=(
                    f"{e.event_type} ({e.action}) on {e.source}"
                    + (f" user='{e.user}'" if e.user else "")
                    + f" from IP {ip}"
                ),
                timestamp=e.timestamp,
                raw_log=e.raw_log,
            )
            for e in all_events
        ]

        window_min = self.window_seconds // 60

        return Alert(
            timestamp=datetime.utcnow(),
            type="ip_sweep",
            severity=self.severity,
            description=(
                f"Coordinated attack detected from IP {ip}: activity seen across "
                f"{len(distinct_sources)} distinct source systems "
                f"({source_list}) within {window_min} minutes."
            ),
            evidence=evidence,
            ai_reasoning=(
                f"Deterministic rule '{self.name}' fired. "
                f"Threshold: {self.min_sources} distinct sources in {self.window_seconds}s. "
                f"Observed: {len(distinct_sources)} sources ({source_list}). "
                f"MITRE {self.mitre_technique} ({self.mitre_tactic})."
            ),
            confidence=1.0,
            recommended_actions=[
                f"Block IP {ip} at the perimeter firewall immediately.",
                "Review all affected systems for signs of compromise.",
                "Check for successful logins from this IP across all systems.",
                "Engage incident response if any system shows a successful login.",
            ],
            fingerprint=make_fingerprint("ip_sweep", ip),
        )
