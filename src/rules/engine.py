import logging
from typing import List, Optional

from src.models import Alert, SecurityEvent
from src.rules.config import load_rules_config
from src.rules.ip_sweep import IPSweepRule
from src.rules.port_scan import PortScanRule
from src.rules.privilege_escalation import PrivilegeEscalationRule
from src.rules.sensitive_file_access import SensitiveFileAccessRule
from src.rules.ssh_brute_force import SSHBruteForceRule

logger = logging.getLogger(__name__)


class RulesEngine:
    """
    Runs all registered deterministic rules against an incoming event.

    Config is loaded once at construction from config/rules.yml (falls back to
    built-in defaults if the file is absent). Rules with `enabled: false` are
    removed at startup and never evaluated.

    Rules run in order and are independent — multiple rules can fire for the
    same event. Each rule catches its own exceptions so one broken rule cannot
    block the others.

    Rules that set `uses_ip_context = True` receive `ip_events` (cross-source
    events sharing the same attacker IP) instead of the standard per-user/
    per-source recent_events list.

    To add a new rule: import it above, append an instance to the list in
    __init__, and add a block for it in config/rules.yml.example.
    """

    def __init__(self) -> None:
        cfg = load_rules_config()

        all_rules = [
            SSHBruteForceRule(config=cfg.get("ssh_brute_force", {})),
            SensitiveFileAccessRule(config=cfg.get("sensitive_file_access", {})),
            PortScanRule(config=cfg.get("port_scan", {})),
            PrivilegeEscalationRule(config=cfg.get("privilege_escalation_after_login", {})),
            IPSweepRule(config=cfg.get("ip_sweep", {})),
        ]

        self._rules = [r for r in all_rules if r.enabled]

        disabled = [r.name for r in all_rules if not r.enabled]
        if disabled:
            logger.info("Rules disabled by config: %s", ", ".join(disabled))
        logger.info(
            "RulesEngine ready with %d active rule(s): %s",
            len(self._rules),
            ", ".join(r.name for r in self._rules),
        )

    @property
    def ip_context_window(self) -> int:
        """
        Returns the maximum window_seconds across all active IP-context rules,
        or 0 if no such rules are enabled.  The worker uses this to decide
        whether to fetch cross-source IP events before calling evaluate().
        """
        windows = [
            r.window_seconds
            for r in self._rules
            if r.uses_ip_context and hasattr(r, "window_seconds")
        ]
        return max(windows) if windows else 0

    def evaluate(
        self,
        event: SecurityEvent,
        recent_events: List[SecurityEvent],
        ip_events: Optional[List[SecurityEvent]] = None,
    ) -> List[Alert]:
        """
        Evaluate all rules and return the list of alerts that fired.

        `ip_events` — cross-source events sharing the same attacker IP,
        pre-fetched by the worker.  Passed as recent_events to rules with
        uses_ip_context=True; ignored by all other rules.

        Returns an empty list when no rule matches.
        """
        ip_events = ip_events or []
        alerts: List[Alert] = []
        for rule in self._rules:
            try:
                context = ip_events if rule.uses_ip_context else recent_events
                if rule.matches(event, context):
                    alert = rule.build_alert(event, context)
                    alerts.append(alert)
                    logger.info(
                        "Rule fired: %s (severity: %s, event_id: %s)",
                        rule.name,
                        rule.severity,
                        event.id,
                    )
            except Exception:
                logger.exception(
                    "Rule '%s' evaluation failed for event_id=%s — skipping",
                    rule.name,
                    event.id,
                )
        return alerts
