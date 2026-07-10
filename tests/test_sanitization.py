"""
Tests for normalizer.py sanitization methods

Tests validate:
- User field sanitization
- Source field sanitization
- Resource field sanitization
- Invalid character rejection
- Length limits
"""
import pytest

from src.normalizer import EventNormalizer


class TestUserSanitization:
    """Test user field sanitization"""
    
    def test_sanitize_user_valid(self):
        """Valid user string passes sanitization"""
        assert EventNormalizer.sanitize_user("user@example.com") == "user@example.com"
        assert EventNormalizer.sanitize_user("admin_user") == "admin_user"
        assert EventNormalizer.sanitize_user("user.name") == "user.name"
    
    def test_sanitize_user_with_whitespace(self):
        """Whitespace is trimmed from user"""
        assert EventNormalizer.sanitize_user("  user123  ") == "user123"
        assert EventNormalizer.sanitize_user("\tadmin\n") == "admin"
    
    def test_sanitize_user_length_limit(self):
        """User longer than 256 chars is truncated"""
        long_user = "a" * 300
        result = EventNormalizer.sanitize_user(long_user)
        assert len(result) == 256
    
    def test_sanitize_user_invalid_characters(self):
        """Invalid characters in user are rejected"""
        with pytest.raises(ValueError):
            EventNormalizer.sanitize_user("user<script>")
        
        with pytest.raises(ValueError):
            EventNormalizer.sanitize_user("user;drop")
        
        with pytest.raises(ValueError):
            EventNormalizer.sanitize_user("user|pipe")
    
    def test_sanitize_user_none(self):
        """None user returns None"""
        assert EventNormalizer.sanitize_user(None) is None
    
    def test_sanitize_user_empty(self):
        """Empty string returns None"""
        assert EventNormalizer.sanitize_user("") is None


class TestSourceSanitization:
    """Test source field sanitization"""
    
    def test_sanitize_source_valid(self):
        """Valid source strings pass"""
        assert EventNormalizer.sanitize_source("web_server") == "web_server"
        assert EventNormalizer.sanitize_source("database.prod") == "database.prod"
        assert EventNormalizer.sanitize_source("api-gateway") == "api-gateway"
    
    def test_sanitize_source_with_whitespace(self):
        """Whitespace is trimmed from source"""
        assert EventNormalizer.sanitize_source("  firewall  ") == "firewall"
        assert EventNormalizer.sanitize_source("\nsyslog\n") == "syslog"
    
    def test_sanitize_source_length_limit(self):
        """Source longer than 256 chars is truncated"""
        long_source = "s" * 300
        result = EventNormalizer.sanitize_source(long_source)
        assert len(result) == 256
    
    def test_sanitize_source_invalid_characters(self):
        """Invalid characters in source are rejected"""
        with pytest.raises(ValueError):
            EventNormalizer.sanitize_source("source<server>")
        
        with pytest.raises(ValueError):
            EventNormalizer.sanitize_source("source;delete")
        
        with pytest.raises(ValueError):
            EventNormalizer.sanitize_source("source@host")


class TestResourceSanitization:
    """Test resource field sanitization"""
    
    def test_sanitize_resource_valid(self):
        """Valid resource strings pass"""
        result = EventNormalizer.sanitize_resource("/admin/panel")
        assert result == "/admin/panel"
        
        result = EventNormalizer.sanitize_resource("C:\\\\Windows\\\\System32")
        assert isinstance(result, str)
    
    def test_sanitize_resource_with_whitespace(self):
        """Whitespace is trimmed from resource"""
        result = EventNormalizer.sanitize_resource("  /path/to/file  ")
        assert result == "/path/to/file"
    
    def test_sanitize_resource_length_limit(self):
        """Resource longer than 1024 chars is truncated"""
        long_resource = "r" * 2000
        result = EventNormalizer.sanitize_resource(long_resource)
        assert len(result) == 1024
    
    def test_sanitize_resource_removes_control_chars(self):
        """Control characters are removed"""
        # Includes null byte and other control chars
        resource_with_control = "/path/file\x00null\x01soh"
        result = EventNormalizer.sanitize_resource(resource_with_control)
        assert "\x00" not in result
        assert "\x01" not in result


class TestSanitizationIntegration:
    """Test sanitization in normalize_event"""
    
    def test_normalize_event_sanitizes_user(self):
        """User is sanitized during normalize_event"""
        raw_event = {
            "timestamp": "2026-06-25T10:00:00Z",
            "source": "test",
            "event_type": "login",
            "user": "  attacker@example.com  "
        }
        
        event = EventNormalizer.normalize_event_full(raw_event)
        assert event.user == "attacker@example.com"
    
    def test_normalize_event_sanitizes_source(self):
        """Source is sanitized during normalize_event"""
        raw_event = {
            "timestamp": "2026-06-25T10:00:00Z",
            "source": "  web_server  ",
            "event_type": "login"
        }
        
        event = EventNormalizer.normalize_event_full(raw_event)
        assert event.source == "web_server"
    
    def test_normalize_event_rejects_invalid_user(self):
        """Invalid user characters are rejected"""
        raw_event = {
            "timestamp": "2026-06-25T10:00:00Z",
            "source": "test",
            "event_type": "login",
            "user": "user<script>alert(1)</script>"
        }
        
        with pytest.raises(ValueError):
            EventNormalizer.normalize_event_full(raw_event)
    
    def test_normalize_event_rejects_invalid_source(self):
        """Invalid source characters are rejected"""
        raw_event = {
            "timestamp": "2026-06-25T10:00:00Z",
            "source": "source;drop table",
            "event_type": "login"
        }
        
        with pytest.raises(ValueError):
            EventNormalizer.normalize_event_full(raw_event)
