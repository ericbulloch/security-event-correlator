from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from src.models import Alert, SecurityEvent


class Rule(ABC):
    """
    Abstract base class for all deterministic detection rules.

    Each rule encodes a single detection pattern inspired by Sigma rule
    structure: a filter (which events qualify), a condition (what pattern
    triggers it), and an output (the alert to create).

    Sigma specification reference:
    https://github.com/SigmaHQ/sigma/blob/master/specification/sigma-rules-specification.md
    """

    # Subclasses declare these as class attributes.
    name: str
    severity: str
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None

    # Set to True on rules that need cross-source IP events instead of the
    # standard per-user/per-source recent_events list.  The engine will pass
    # ip_events (fetched by the worker) as recent_events for these rules.
    uses_ip_context: bool = False

    def __init__(self, config: Dict[str, Any]) -> None:
        """
        `config` is the rule's block from config/rules.yml (may be empty if
        the file is absent or the rule has no entry — subclasses must always
        provide safe defaults via config.get("key", default)).
        """
        self.enabled: bool = config.get("enabled", True)
        self._config = config

    @abstractmethod
    def matches(
        self,
        event: SecurityEvent,
        recent_events: List[SecurityEvent],
    ) -> bool:
        """
        Return True if this rule fires for the given event + its recent context.

        `recent_events` contains events fetched by the worker's correlation
        window query — same user, same source, related event types, within
        the lookback window. Rules should not perform their own DB queries.
        """

    @abstractmethod
    def build_alert(
        self,
        event: SecurityEvent,
        recent_events: List[SecurityEvent],
    ) -> Alert:
        """Build and return the Alert to store when this rule fires."""
