"""
Pytest configuration and shared fixtures for all tests.
"""
import pytest
from datetime import datetime, timezone


@pytest.fixture
def valid_timestamp():
    """Returns a valid UTC timestamp (now)"""
    return datetime.now(timezone.utc)


@pytest.fixture
def valid_iso_timestamp():
    """Returns a valid ISO 8601 UTC timestamp string"""
    return "2026-06-25T10:00:00Z"


@pytest.fixture
def valid_unix_timestamp():
    """Returns a valid Unix timestamp (5 minutes ago)"""
    return 1719321600  # 2026-06-25T10:00:00Z


@pytest.fixture
def valid_event_dict():
    """Returns a valid event dictionary"""
    return {
        "timestamp": "2026-06-25T10:00:00Z",
        "source": "web_server",
        "event_type": "login_attempt",
        "severity": "medium",
        "action": "failed",
        "user": "attacker@example.com",
        "resource": "admin_panel",
        "details": {"ip": "192.168.1.1", "attempts": 5}
    }
