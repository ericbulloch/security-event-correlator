from datetime import datetime
import re
from typing import Dict, Any

from src.models import SecurityEvent
from src.timestamp_validator import TimestampValidator


class EventNormalizer:
    SEVERITY_MAP = {
        'low': 'low',
        'info': 'low',
        'informational': 'low',
        'debug': 'low',
        
        'medium': 'medium',
        'warn': 'medium',
        'warning': 'medium',
        
        'high': 'high',
        'error': 'high',
        'err': 'high',
        
        'critical': 'critical',
        'alert': 'critical',
        'emergency': 'critical',
        'fatal': 'critical',
    }
    
    EVENT_TYPE_MAP = {
        'login': 'login_attempt',
        'authentication': 'login_attempt',
        'auth': 'login_attempt',
        'ssh_login': 'login_attempt',
        'rdp_login': 'login_attempt',
        
        'http': 'http_request',
        'web': 'http_request',
        'request': 'http_request',
        'get': 'http_request',
        'post': 'http_request',
        
        'query': 'database_query',
        'sql': 'database_query',
        'db_access': 'database_query',
        'database': 'database_query',
        
        'file_access': 'file_access',
        'file_open': 'file_access',
        'file_read': 'file_access',
        'file_write': 'file_access',
        
        'privilege_escalation': 'privilege_change',
        'privilege_change': 'privilege_change',
        'sudo': 'privilege_change',
        'privilege_elevation': 'privilege_change',
        
        'connection': 'network_connection',
        'network': 'network_connection',
        'outbound': 'network_connection',
        'inbound': 'network_connection',
    }
    
    @staticmethod
    def normalize_severity(severity_str: str) -> str:
        normalized = severity_str.lower().strip()
        return EventNormalizer.SEVERITY_MAP.get(normalized, 'low')
    
    @staticmethod
    def normalize_event_type(event_type_str: str) -> str:
        normalized = event_type_str.lower().strip()
        return EventNormalizer.EVENT_TYPE_MAP.get(normalized, normalized)
    
    @staticmethod
    def normalize_action(action_str: str) -> str:
        action_lower = action_str.lower().strip()
        if action_lower in ['success', 'ok', '200', 'succeeded', 'allowed', 'granted', 'yes']:
            return 'succeeded'
        if action_lower in ['failed', 'failure', 'error', '401', '403', '404', '500', 'denied', 'rejected', 'blocked']:
            return 'failed'
        return action_lower
    
    @staticmethod
    def extract_ip_from_details(details: Dict[str, Any]) -> str:
        ip_fields = ['ip', 'source_ip', 'origin_ip', 'client_ip', 'remote_ip', 'src_ip']
        for field in ip_fields:
            if field in details and details[field]:
                return str(details[field])
        return None
    
    @staticmethod
    def enrich_event(event: SecurityEvent) -> SecurityEvent:
        # If severity is low but event_type suggests it should be higher, adjust
        if event.severity == 'low':
            high_risk_types = ['privilege_change', 'network_connection', 'file_access']
            if event.event_type in high_risk_types:
                event.severity = 'medium'
        if 'ip' not in event.details and event.details:
            ip = EventNormalizer.extract_ip_from_details(event.details)
            if ip:
                event.details['ip'] = ip
        return event
    
    @staticmethod
    def normalize_timestamp(timestamp_input: Any) -> datetime:
        return TimestampValidator.validate(timestamp_input)

    @staticmethod
    def sanitize_user(value: str) -> Optional[str]:
        if not value:
            return None
        value = value.strip()[:256]
        if not re.match(r'^[a-zA-Z0-9._\-@\\]{1,256}$', value):
            raise ValueError("Invalid characters in user field")
        return value

    @staticmethod
    def sanitize_source(value: str) -> Optional[str]:
        value = value.strip()[:256]
        if not re.match(r'^[a-zA-Z0-9._\-]{1,256}$', value):
            raise ValueError("Invalid characters in source field")
        return value

    @staticmethod
    def sanitize_resource(value: str) -> Optional[str]:
        value = value.strip()[:1024]
        value = re.sub(r'[\x00-\x1f\x7f]', '', value)
        return value

def normalize_event(raw_event: Dict[str, Any]) -> SecurityEvent:
    if 'timestamp' not in raw_event:
        raise ValueError("Timestamp is required for all events")
    timestamp = EventNormalizer.normalize_timestamp(
        raw_event.get('timestamp')
    )
    source = raw_event.get('source', 'unknown').lower().strip()
    source = EventNormalizer.sanitize_source(source)
    event_type = EventNormalizer.normalize_event_type(
        raw_event.get('event_type', 'unknown')
    )
    severity = EventNormalizer.normalize_severity(
        raw_event.get('severity', 'low')
    )
    user = raw_event.get('user', None)
    user = EventNormalizer.sanitize_user(user)
    action = EventNormalizer.normalize_action(
        raw_event.get('action', 'unknown')
    )
    resource = raw_event.get('resource', None)
    resource = EventNormalizer.sanitize_resource(resource)
    details = raw_event.get('details', {})
    if not isinstance(details, dict):
        details = {}
    event = SecurityEvent(
        timestamp=timestamp,
        source=source,
        event_type=event_type,
        severity=severity,
        user=user,
        action=action,
        resource=resource,
        details=details
    )
    event = EventNormalizer.enrich_event(event)
    return event
