"""
Tests for storage.py - API key and alert management

Tests validate:
- API key creation and retrieval
- Alert pagination and filtering
- Count operations
- Database operations
"""
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from src.storage import EventStore
from src.models import Alert


class TestAPIKeyManagement:
    """Test API key CRUD operations"""
    
    def test_create_api_key(self):
        """Create API key in database"""
        store = EventStore(db_path=":memory:")
        
        store.create_api_key(
            key_hash="test_hash_123",
            client_name="test_client",
            rate_limit=100
        )
        
        # Verify it was created by attempting to retrieve it
        result = store.get_api_key("test_hash_123")
        assert result is not None
        assert result['client_name'] == 'test_client'
    
    def test_get_api_key_returns_dict(self):
        """get_api_key returns dict with all fields"""
        store = EventStore(db_path=":memory:")
        
        store.create_api_key(
            key_hash="test_hash_456",
            client_name="client_456",
            rate_limit=50
        )
        
        result = store.get_api_key("test_hash_456")
        
        assert isinstance(result, dict)
        assert 'id' in result
        assert 'key_hash' in result
        assert 'client_name' in result
        assert 'is_active' in result
        assert 'rate_limit' in result
    
    def test_get_nonexistent_api_key(self):
        """Get non-existent API key returns None"""
        store = EventStore(db_path=":memory:")
        
        result = store.get_api_key("nonexistent_hash")
        assert result is None
    
    def test_update_last_used(self):
        """Update last_used_at timestamp"""
        store = EventStore(db_path=":memory:")
        
        store.create_api_key(
            key_hash="test_hash_789",
            client_name="client_789",
            rate_limit=100
        )
        
        # Get the key to get its ID
        key_record = store.get_api_key("test_hash_789")
        key_id = key_record['id']
        
        # Update last used
        store.update_last_used(key_id)
        
        # Verify it was updated
        updated = store.get_api_key("test_hash_789")
        assert updated['last_used_at'] is not None


class TestAlertPagination:
    """Test alert retrieval with pagination"""
    
    def test_get_alerts_with_pagination(self):
        """Retrieve alerts with limit and offset"""
        store = EventStore(db_path=":memory:")
        
        # Create multiple alerts
        for i in range(10):
            alert = Alert(
                type=f"alert_type_{i}",
                severity="high",
                description=f"Test alert {i}",
                evidence=[],
                ai_reasoning="test",
                confidence=0.9,
                recommended_actions=[],
                timestamp=datetime.now(timezone.utc)
            )
            store.add_alert(alert)
        
        # Get first 5
        alerts = store.get_alerts(limit=5, offset=0, severity=None)
        assert len(alerts) == 5
        
        # Get next 5
        alerts = store.get_alerts(limit=5, offset=5, severity=None)
        assert len(alerts) == 5
    
    def test_get_alerts_with_severity_filter(self):
        """Filter alerts by severity"""
        store = EventStore(db_path=":memory:")
        
        # Create alerts with different severities
        for severity in ["low", "medium", "high", "critical"]:
            alert = Alert(
                type="test_type",
                severity=severity,
                description="Test",
                evidence=[],
                ai_reasoning="test",
                confidence=0.9,
                recommended_actions=[],
                timestamp=datetime.now(timezone.utc)
            )
            store.add_alert(alert)
        
        # Get only high severity
        alerts = store.get_alerts(limit=100, offset=0, severity="high")
        assert len(alerts) == 1
        assert alerts[0].severity == "high"
        
        # Get critical severity
        alerts = store.get_alerts(limit=100, offset=0, severity="critical")
        assert len(alerts) == 1
        assert alerts[0].severity == "critical"
    
    def test_get_alerts_no_filter(self):
        """Get alerts without severity filter"""
        store = EventStore(db_path=":memory:")
        
        # Add 3 alerts
        for i in range(3):
            alert = Alert(
                type=f"type_{i}",
                severity="low",
                description=f"Alert {i}",
                evidence=[],
                ai_reasoning="test",
                confidence=0.9,
                recommended_actions=[],
                timestamp=datetime.now(timezone.utc)
            )
            store.add_alert(alert)
        
        alerts = store.get_alerts(limit=100, offset=0, severity=None)
        assert len(alerts) == 3


class TestAlertCounting:
    """Test alert counting"""
    
    def test_count_all_alerts(self):
        """Count total alerts in database"""
        store = EventStore(db_path=":memory:")
        
        # Add 5 alerts
        for i in range(5):
            alert = Alert(
                type="test",
                severity="low",
                description=f"Alert {i}",
                evidence=[],
                ai_reasoning="test",
                confidence=0.9,
                recommended_actions=[],
                timestamp=datetime.now(timezone.utc)
            )
            store.add_alert(alert)
        
        count = store.count_alerts()
        assert count == 5
    
    def test_count_alerts_empty_database(self):
        """Count alerts when database is empty"""
        store = EventStore(db_path=":memory:")
        
        count = store.count_alerts()
        assert count == 0


class TestAPIKeyTable:
    """Test API key table structure"""
    
    def test_api_keys_table_created(self):
        """API keys table is created during initialization"""
        store = EventStore(db_path=":memory:")
        
        # Try to insert a key - should work if table exists
        store.create_api_key(
            key_hash="test_hash",
            client_name="test",
            rate_limit=100
        )
        
        result = store.get_api_key("test_hash")
        assert result is not None
    
    def test_api_key_defaults(self):
        """API key has correct defaults"""
        store = EventStore(db_path=":memory:")
        
        store.create_api_key(
            key_hash="hash_defaults",
            client_name="client_defaults"
        )
        
        result = store.get_api_key("hash_defaults")
        assert result['is_active'] == 1
        assert result['rate_limit'] == 100
        assert result['created_at'] is not None
