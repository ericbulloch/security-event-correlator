"""
Tests for normalizer.py

Tests validate:
- Event normalization
- Severity mapping
- Event type mapping
- Action normalization
- IP extraction
- Event enrichment
- Complete event normalization
"""
import pytest
from datetime import datetime, timezone

from src.normalizer import EventNormalizer, normalize_event
from src.models import SecurityEvent


class TestEventNormalizerSeverity:
    """Test severity normalization"""
    
    def test_normalize_severity_low_variants(self):
        """Normalize various low severity strings"""
        low_variants = ['low', 'LOW', 'info', 'INFO', 'informational', 'debug', 'DEBUG']
        for variant in low_variants:
            assert EventNormalizer.normalize_severity(variant) == 'low'
    
    def test_normalize_severity_medium_variants(self):
        """Normalize various medium severity strings"""
        medium_variants = ['medium', 'MEDIUM', 'warn', 'warning', 'WARNING']
        for variant in medium_variants:
            assert EventNormalizer.normalize_severity(variant) == 'medium'
    
    def test_normalize_severity_high_variants(self):
        """Normalize various high severity strings"""
        high_variants = ['high', 'HIGH', 'error', 'err', 'ERROR']
        for variant in high_variants:
            assert EventNormalizer.normalize_severity(variant) == 'high'
    
    def test_normalize_severity_critical_variants(self):
        """Normalize various critical severity strings"""
        critical_variants = ['critical', 'CRITICAL', 'alert', 'emergency', 'fatal']
        for variant in critical_variants:
            assert EventNormalizer.normalize_severity(variant) == 'critical'
    
    def test_normalize_severity_with_whitespace(self):
        """Handle severity strings with extra whitespace"""
        assert EventNormalizer.normalize_severity('  high  ') == 'high'
        assert EventNormalizer.normalize_severity('\tmedium\n') == 'medium'
    
    def test_normalize_severity_unknown_defaults_to_low(self):
        """Unknown severity defaults to low"""
        assert EventNormalizer.normalize_severity('unknown') == 'low'
        assert EventNormalizer.normalize_severity('SUPER_CRITICAL') == 'low'


class TestEventNormalizerEventType:
    """Test event type normalization"""
    
    def test_normalize_event_type_login_variants(self):
        """Normalize various login event type strings"""
        login_variants = ['login', 'authentication', 'auth', 'ssh_login', 'rdp_login']
        for variant in login_variants:
            assert EventNormalizer.normalize_event_type(variant) == 'login_attempt'
    
    def test_normalize_event_type_http_variants(self):
        """Normalize various HTTP event type strings"""
        http_variants = ['http', 'web', 'request', 'get', 'post']
        for variant in http_variants:
            assert EventNormalizer.normalize_event_type(variant) == 'http_request'
    
    def test_normalize_event_type_database_variants(self):
        """Normalize various database event type strings"""
        db_variants = ['query', 'sql', 'db_access', 'database']
        for variant in db_variants:
            assert EventNormalizer.normalize_event_type(variant) == 'database_query'
    
    def test_normalize_event_type_file_access_variants(self):
        """Normalize various file access event type strings"""
        file_variants = ['file_access', 'file_open', 'file_read', 'file_write']
        for variant in file_variants:
            assert EventNormalizer.normalize_event_type(variant) == 'file_access'
    
    def test_normalize_event_type_privilege_change_variants(self):
        """Normalize various privilege escalation strings"""
        priv_variants = ['privilege_escalation', 'privilege_change', 'sudo', 'privilege_elevation']
        for variant in priv_variants:
            assert EventNormalizer.normalize_event_type(variant) == 'privilege_change'
    
    def test_normalize_event_type_network_variants(self):
        """Normalize various network connection strings"""
        network_variants = ['connection', 'network', 'outbound', 'inbound']
        for variant in network_variants:
            assert EventNormalizer.normalize_event_type(variant) == 'network_connection'
    
    def test_normalize_event_type_unknown_returns_as_is(self):
        """Unknown event types are returned as normalized lowercase"""
        assert EventNormalizer.normalize_event_type('CUSTOM_EVENT') == 'custom_event'
        assert EventNormalizer.normalize_event_type('NEW_TYPE') == 'new_type'
    
    def test_normalize_event_type_case_insensitive(self):
        """Event type normalization is case insensitive"""
        assert EventNormalizer.normalize_event_type('LOGIN') == 'login_attempt'
        assert EventNormalizer.normalize_event_type('Http') == 'http_request'


class TestEventNormalizerAction:
    """Test action normalization"""
    
    def test_normalize_action_success_variants(self):
        """Normalize various success action strings"""
        success_variants = ['success', 'ok', '200', 'succeeded', 'allowed', 'granted', 'yes']
        for variant in success_variants:
            assert EventNormalizer.normalize_action(variant) == 'succeeded'
    
    def test_normalize_action_failed_variants(self):
        """Normalize various failure action strings"""
        failed_variants = ['failed', 'failure', 'error', '401', '403', '404', '500', 'denied', 'rejected', 'blocked']
        for variant in failed_variants:
            assert EventNormalizer.normalize_action(variant) == 'failed'
    
    def test_normalize_action_case_insensitive(self):
        """Action normalization is case insensitive"""
        assert EventNormalizer.normalize_action('SUCCESS') == 'succeeded'
        assert EventNormalizer.normalize_action('FAILED') == 'failed'
        assert EventNormalizer.normalize_action('Ok') == 'succeeded'
    
    def test_normalize_action_with_whitespace(self):
        """Handle action strings with whitespace"""
        assert EventNormalizer.normalize_action('  success  ') == 'succeeded'
        assert EventNormalizer.normalize_action('\tfailed\n') == 'failed'
    
    def test_normalize_action_unknown_returns_as_is(self):
        """Unknown actions are returned as normalized lowercase"""
        assert EventNormalizer.normalize_action('PENDING') == 'pending'
        assert EventNormalizer.normalize_action('UNKNOWN') == 'unknown'


class TestEventNormalizerIPExtraction:
    """Test IP extraction from event details"""
    
    def test_extract_ip_from_ip_field(self):
        """Extract IP from 'ip' field"""
        details = {'ip': '192.168.1.1'}
        result = EventNormalizer.extract_ip_from_details(details)
        assert result == '192.168.1.1'
    
    def test_extract_ip_from_source_ip_field(self):
        """Extract IP from 'source_ip' field"""
        details = {'source_ip': '10.0.0.1'}
        result = EventNormalizer.extract_ip_from_details(details)
        assert result == '10.0.0.1'
    
    def test_extract_ip_from_client_ip_field(self):
        """Extract IP from 'client_ip' field"""
        details = {'client_ip': '172.16.0.1'}
        result = EventNormalizer.extract_ip_from_details(details)
        assert result == '172.16.0.1'
    
    def test_extract_ip_priority_order(self):
        """IP extraction follows priority: ip > source_ip > origin_ip > client_ip > remote_ip > src_ip"""
        # When multiple IP fields exist, should use first in priority
        details = {
            'remote_ip': '1.1.1.1',
            'client_ip': '2.2.2.2',
            'source_ip': '3.3.3.3',
            'ip': '4.4.4.4'
        }
        result = EventNormalizer.extract_ip_from_details(details)
        assert result == '4.4.4.4'  # 'ip' has highest priority
    
    def test_extract_ip_no_ip_fields(self):
        """Return None when no IP fields in details"""
        details = {'other': 'value', 'data': 'here'}
        result = EventNormalizer.extract_ip_from_details(details)
        assert result is None
    
    def test_extract_ip_empty_details(self):
        """Return None for empty details"""
        result = EventNormalizer.extract_ip_from_details({})
        assert result is None
    
    def test_extract_ip_converts_to_string(self):
        """IP values are converted to string"""
        details = {'ip': 192}  # Non-string IP
        result = EventNormalizer.extract_ip_from_details(details)
        assert result == '192'
        assert isinstance(result, str)


class TestEventNormalizerEnrichment:
    """Test event enrichment"""
    
    def test_enrich_event_low_severity_privilege_escalation(self):
        """Enrich low severity privilege_change to medium"""
        event = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            source='test',
            event_type='privilege_change',
            severity='low',
            user='test',
            action='succeeded',
            resource='test',
            details={}
        )
        enriched = EventNormalizer.enrich_event(event)
        assert enriched.severity == 'medium'
    
    def test_enrich_event_low_severity_network_connection(self):
        """Enrich low severity network_connection to medium"""
        event = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            source='test',
            event_type='network_connection',
            severity='low',
            user='test',
            action='succeeded',
            resource='test',
            details={}
        )
        enriched = EventNormalizer.enrich_event(event)
        assert enriched.severity == 'medium'
    
    def test_enrich_event_low_severity_file_access(self):
        """Enrich low severity file_access to medium"""
        event = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            source='test',
            event_type='file_access',
            severity='low',
            user='test',
            action='succeeded',
            resource='test',
            details={}
        )
        enriched = EventNormalizer.enrich_event(event)
        assert enriched.severity == 'medium'
    
    def test_enrich_event_low_severity_safe_type(self):
        """Don't enrich low severity for safe event types"""
        event = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            source='test',
            event_type='login_attempt',
            severity='low',
            user='test',
            action='succeeded',
            resource='test',
            details={}
        )
        enriched = EventNormalizer.enrich_event(event)
        assert enriched.severity == 'low'  # Should not change
    
    def test_enrich_event_extract_ip_from_details(self):
        """Extract IP from details during enrichment"""
        event = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            source='test',
            event_type='login_attempt',
            severity='low',
            user='test',
            action='failed',
            resource='test',
            details={'source_ip': '192.168.1.100'}
        )
        enriched = EventNormalizer.enrich_event(event)
        assert 'ip' in enriched.details
        assert enriched.details['ip'] == '192.168.1.100'
    
    def test_enrich_event_preserve_existing_ip(self):
        """Don't overwrite existing IP field"""
        event = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            source='test',
            event_type='login_attempt',
            severity='low',
            user='test',
            action='failed',
            resource='test',
            details={'ip': '10.0.0.1', 'source_ip': '192.168.1.100'}
        )
        enriched = EventNormalizer.enrich_event(event)
        assert enriched.details['ip'] == '10.0.0.1'  # Original preserved


class TestNormalizeEventFunction:
    """Test the normalize_event function"""
    
    def test_normalize_event_complete_valid_event(self):
        """Normalize a complete valid event"""
        raw_event = {
            'timestamp': '2026-06-25T10:00:00Z',
            'source': 'WEB_SERVER',
            'event_type': 'login',
            'severity': 'HIGH',
            'action': 'FAILED',
            'user': 'ATTACKER@EXAMPLE.COM',
            'resource': 'ADMIN_PANEL',
            'details': {'source_ip': '192.168.1.1', 'attempts': 5}
        }
        
        event = normalize_event(raw_event)
        
        assert event.source == 'web_server'  # Lowercase
        assert event.event_type == 'login_attempt'  # Mapped
        assert event.severity == 'high'  # Normalized
        assert event.action == 'failed'  # Normalized
        assert event.user == 'attacker@example.com'  # Lowercase
        assert event.resource == 'admin_panel'  # Stripped/normalized
        assert event.details['ip'] == '192.168.1.1'  # Enriched with IP
    
    def test_normalize_event_missing_timestamp_raises_error(self):
        """Raise error if timestamp is missing"""
        raw_event = {
            'source': 'test',
            'event_type': 'login',
            'severity': 'low',
            'action': 'succeeded'
        }
        
        with pytest.raises(ValueError) as exc_info:
            normalize_event(raw_event)
        assert "timestamp" in str(exc_info.value).lower()
    
    def test_normalize_event_with_defaults(self):
        """Normalize event with minimal data using defaults"""
        raw_event = {
            'timestamp': '2026-06-25T10:00:00Z'
        }
        
        event = normalize_event(raw_event)
        
        assert event.source == 'unknown'  # Default
        assert event.event_type == 'unknown'  # Default
        assert event.severity == 'low'  # Default
        assert event.action == 'unknown'  # Default
        assert event.user is None  # Default
        assert event.resource is None  # Default
        assert event.details == {}  # Default
    
    def test_normalize_event_invalid_details_dict(self):
        """Handle non-dict details gracefully"""
        raw_event = {
            'timestamp': '2026-06-25T10:00:00Z',
            'source': 'test',
            'event_type': 'login',
            'severity': 'low',
            'action': 'succeeded',
            'details': 'not_a_dict'  # Invalid
        }
        
        event = normalize_event(raw_event)
        assert event.details == {}  # Converted to empty dict
    
    def test_normalize_event_enrichment_applied(self):
        """Verify enrichment is applied in normalize_event"""
        raw_event = {
            'timestamp': '2026-06-25T10:00:00Z',
            'source': 'test',
            'event_type': 'privilege_escalation',  # Will be mapped to privilege_change
            'severity': 'low',  # Will be enriched to medium
            'action': 'succeeded',
            'details': {}
        }
        
        event = normalize_event(raw_event)
        
        assert event.event_type == 'privilege_change'  # Mapped
        assert event.severity == 'medium'  # Enriched
    
    def test_normalize_event_whitespace_handling(self):
        """Handle fields with extra whitespace"""
        raw_event = {
            'timestamp': '2026-06-25T10:00:00Z',
            'source': '  WEB_SERVER  ',
            'event_type': 'login',
            'severity': 'high',
            'action': 'failed',
            'user': '  ADMIN  ',
            'resource': '  /admin/panel  '
        }
        
        event = normalize_event(raw_event)
        
        assert event.source == 'web_server'  # Stripped and lowercased
        assert event.user == 'admin'  # Stripped and lowercased
        assert event.resource == '/admin/panel'  # Stripped
    
    def test_normalize_event_returns_security_event(self):
        """Verify normalize_event returns SecurityEvent object"""
        raw_event = {
            'timestamp': '2026-06-25T10:00:00Z',
            'source': 'test',
            'event_type': 'login'
        }
        
        event = normalize_event(raw_event)
        assert isinstance(event, SecurityEvent)
