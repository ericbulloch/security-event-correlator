from src.models import SecurityEvent


class CorrelationRule:
    @staticmethod
    def should_process(event: SecurityEvent) -> bool:
        if event.severity in ['high', 'critical']:
            return True
        attack_indicators = [
            'privilege_change', 'network_connection', 'file_access'
        ]
        if event.event_type in attack_indicators:
            return True
        if event.event_type == 'login_attempt' and event.action == 'failed':
            return True
        if event.event_type == 'database_query':
            return True
        if event.severity == 'low' and event.action == 'succeeded':
            return False
        
        return True
    
    @staticmethod
    def get_lookback_window(event: SecurityEvent) -> int:
        if event.event_type == 'login_attempt':
            return 60  # Look back 1 minute
        if event.event_type == 'database_query' or event.event_type == 'network_connection':
            return 300  # Look back 5 minutes
        if event.event_type == 'file_access':
            return 3600  # Look back 1 hour
        
        return 300
    
    @staticmethod
    def get_related_event_types(event: SecurityEvent) -> list[str]:
        if event.event_type == 'login_attempt':
            return ['login_attempt', 'privilege_change']
        if event.event_type == 'database_query':
            return ['login_attempt', 'database_query', 'network_connection']
        if event.event_type == 'network_connection':
            return ['database_query', 'network_connection', 'file_access']
        if event.event_type == 'file_access':
            return ['file_access', 'network_connection', 'login_attempt']
        if event.event_type == 'privilege_change':
            # Include login_attempt so the PrivilegeEscalationRule can check
            # whether a successful login preceded this privilege change.
            return ['privilege_change', 'login_attempt']

        return [event.event_type]
