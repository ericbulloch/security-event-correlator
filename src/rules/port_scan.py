"""
Port Scan detection rule.

Detects a high volume of outbound or inbound network connection events from
the same source system within a short time window, which is characteristic
of automated port scanning tools (nmap, masscan, etc.).

Sigma rule reference:
  https://github.com/SigmaHQ/sigma/blob/master/rules/network/net_scan_ports.yml
MITRE ATT&CK: T1046 — Network Service Discovery
Tactic: TA0007 — Discovery

Limitation: get_events_for_correlation filters by (user, source). If the
triggering event has user=None the correlation query will return no context
because PostgreSQL evaluates NULL = NULL as false. Port scan events that
arrive without a user field will still trigger on their own count of 1,
which is below any reasonable threshold. This is an acceptable trade-off for
now; a future improvement would add a separate IP-indexed query path.
"""

from datetime import datetime
from typing import Any, Dict, List

from src.models import Alert, Evidence, SecurityEvent, make_fingerprint
from src.rules.base import Rule

_DEFAULT_THRESHOLD = 10
_DEFAULT_WINDOW_SECONDS = 300


class PortScanRule(Rule):
    name = "port_scan"
    severity = "medium"
    mitre_technique = "T1046"
    mitre_tactic = "TA0007"

    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        self.threshold: int = config.get("threshold", _DEFAULT_THRESHOLD)
        self.window_seconds: int = config.get("window_seconds", _DEFAULT_WINDOW_SECONDS)

    def _connection_events(
        self, event: SecurityEvent, recent_events: List[SecurityEvent]
    ) -> List[SecurityEvent]:
        return [
            e for e in recent_events if e.event_type == "network_connection"
        ]

    def matches(
        self, event: SecurityEvent, recent_events: List[SecurityEvent]
    ) -> bool:
        if event.event_type != "network_connection":
            return False
        prior = self._connection_events(event, recent_events)
        return (len(prior) + 1) >= self.threshold

    def build_alert(
        self, event: SecurityEvent, recent_events: List[SecurityEvent]
    ) -> Alert:
        prior = self._connection_events(event, recent_events)
        all_connections = prior + [event]
        all_connections.sort(key=lambda e: e.timestamp)

        target_user = event.user or "unknown"
        total = len(all_connections)

        # Collect distinct destination ports when available.
        ports = sorted(
            {
                str(e.details.get("port") or e.details.get("destination_port") or "")
                for e in all_connections
                if e.details
            }
            - {""}
        )
        port_clause = f" across {len(ports)} distinct port(s)" if ports else ""

        evidence = [
            Evidence(
                event=(
                    f"Network connection by '{e.user or 'unknown'}' on {e.source}"
                    + (
                        f" to port {e.details.get('port') or e.details.get('destination_port')}"
                        if e.details and (e.details.get("port") or e.details.get("destination_port"))
                        else ""
                    )
                ),
                timestamp=e.timestamp,
                raw_log=e.raw_log,
            )
            for e in all_connections
        ]

        return Alert(
            timestamp=datetime.utcnow(),
            type="port_scan",
            severity=self.severity,
            description=(
                f"Possible port scan: {total} network connection events "
                f"from user '{target_user}' on {event.source}{port_clause} "
                f"within {self.window_seconds} seconds."
            ),
            evidence=evidence,
            ai_reasoning=(
                f"Deterministic rule '{self.name}' fired. "
                f"Threshold: {self.threshold} connections in {self.window_seconds}s. "
                f"Observed: {total}. "
                f"MITRE {self.mitre_technique} ({self.mitre_tactic})."
            ),
            confidence=0.8,
            recommended_actions=[
                f"Identify the process generating connections on '{event.source}'.",
                "Check for scanning tools (nmap, masscan, netcat) in the process list.",
                "Review firewall logs for the corresponding traffic.",
                "Isolate the system if scanning is confirmed and unexpected.",
            ],
            fingerprint=make_fingerprint(
                "port_scan", event.user or "", event.source
            ),
        )
