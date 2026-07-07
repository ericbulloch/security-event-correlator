from typing import List, Optional
from datetime import datetime, timedelta, UTC
import json
import os
import logging

import psycopg
from psycopg.rows import dict_row

from src.models import Alert, Evidence, SecurityEvent

logger = logging.getLogger(__name__)


class EventStore:
    def __init__(self, connection_string: Optional[str] = None):
        self.connection_string = connection_string or os.getenv(
            "DATABASE_URL",
            "postgresql://localhost/security_events"
        )
        self._init_database()
    
    def _get_connection(self):
        try:
            return psycopg.connect(self.connection_string)
        except psycopg.Error as e:
            logger.error(f"Failed to connect to PostgreSQL: {str(e)}")
            raise
    
    def _init_database(self):
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            
            # Events table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP NOT NULL,
                    source VARCHAR(256) NOT NULL,
                    event_type VARCHAR(256) NOT NULL,
                    severity VARCHAR(50) NOT NULL,
                    "user" VARCHAR(256),
                    action VARCHAR(256) NOT NULL,
                    resource VARCHAR(1024),
                    details JSONB NOT NULL,
                    processed INTEGER DEFAULT 0,
                    processed_at TIMESTAMP,
                    correlation_id UUID,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP NOT NULL,
                    type VARCHAR(256) NOT NULL,
                    severity VARCHAR(50) NOT NULL,
                    description TEXT NOT NULL,
                    evidence JSONB NOT NULL,
                    ai_reasoning TEXT NOT NULL,
                    confidence FLOAT NOT NULL,
                    recommended_actions JSONB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Rate limits table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS rate_limits (
                    id SERIAL PRIMARY KEY,
                    client_name VARCHAR(256) NOT NULL,
                    request_count INTEGER DEFAULT 0,
                    window_start TIMESTAMP NOT NULL,
                    UNIQUE(client_name, window_start)
                )
            ''')
            
            # API keys table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS api_keys (
                    id SERIAL PRIMARY KEY,
                    key_hash VARCHAR(64) NOT NULL UNIQUE,
                    client_name VARCHAR(256) NOT NULL,
                    is_active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used_at TIMESTAMP,
                    expires_at TIMESTAMP,
                    rate_limit INTEGER NOT NULL DEFAULT 100
                )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_source ON events(source)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_processed ON events(processed)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_correlation_id ON events(correlation_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_user ON events("user")')
            
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
            
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_rate_limits_client_window ON rate_limits(client_name, window_start)')
            
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_api_keys_client ON api_keys(client_name)')
            
            conn.commit()
            logger.info("Database initialized successfully")
        except psycopg.Error as e:
            conn.rollback()
            logger.error(f"Failed to initialize database: {str(e)}")
            raise
        finally:
            conn.close()
    
    def add_security_event(self, event: SecurityEvent) -> SecurityEvent:
        event_id = self._event_to_database(event)
        event.id = event_id
        return event

    def add_alert(self, alert: Alert) -> Alert:
        alert_id = self._alert_to_database(alert)
        alert.id = alert_id
        return alert
    
    def _event_to_database(self, event: SecurityEvent) -> int:
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO events 
                (timestamp, source, event_type, severity, "user", action, resource, details)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            ''', (
                event.timestamp,
                event.source,
                event.event_type,
                event.severity,
                event.user,
                event.action,
                event.resource,
                json.dumps(event.details)
            ))
            event_id = cursor.fetchone()[0]
            conn.commit()
            return event_id
        except psycopg.Error as e:
            conn.rollback()
            logger.error(f"Failed to insert event: {str(e)}")
            raise
        finally:
            conn.close()

    def _alert_to_database(self, alert: Alert) -> int:
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO alerts 
                (timestamp, type, severity, description, evidence, ai_reasoning, confidence, recommended_actions)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            ''', (
                alert.timestamp,
                alert.type,
                alert.severity,
                alert.description,
                json.dumps([ev.dict() for ev in alert.evidence]),
                alert.ai_reasoning,
                alert.confidence,
                json.dumps(alert.recommended_actions)
            ))
            alert_id = cursor.fetchone()[0]
            conn.commit()
            return alert_id
        except psycopg.Error as e:
            conn.rollback()
            logger.error(f"Failed to insert alert: {str(e)}")
            raise
        finally:
            conn.close()

    def get_alerts(self, limit: int, offset: int, severity: Optional[str] = None) -> List[Alert]:
        conn = self._get_connection()
        try:
            cursor = conn.cursor(row_factory=dict_row)
            
            if severity:
                cursor.execute('''
                    SELECT * FROM alerts 
                    WHERE severity = %s 
                    ORDER BY timestamp DESC 
                    LIMIT %s OFFSET %s
                ''', (severity, limit, offset))
            else:
                cursor.execute('''
                    SELECT * FROM alerts 
                    ORDER BY timestamp DESC 
                    LIMIT %s OFFSET %s
                ''', (limit, offset))
            
            rows = cursor.fetchall()
            alerts = []
            
            for row in rows:
                evidence_list = row['evidence'] if isinstance(row['evidence'], list) else []
                evidence_objects = [
                    Evidence(**ev) if isinstance(ev, dict) else ev 
                    for ev in evidence_list
                ]
                
                alert = Alert(
                    id=row['id'],
                    timestamp=row['timestamp'],
                    type=row['type'],
                    severity=row['severity'],
                    description=row['description'],
                    evidence=evidence_objects,
                    ai_reasoning=row['ai_reasoning'],
                    confidence=row['confidence'],
                    recommended_actions=row['recommended_actions']
                )
                alerts.append(alert)
            
            return alerts
        except psycopg.Error as e:
            logger.error(f"Failed to retrieve alerts: {str(e)}")
            raise
        finally:
            conn.close()

    def count_alerts(self, severity: Optional[str] = None) -> int:
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            
            if severity:
                cursor.execute('SELECT COUNT(*) FROM alerts WHERE severity = %s', (severity,))
            else:
                cursor.execute('SELECT COUNT(*) FROM alerts')
            
            count = cursor.fetchone()[0]
            return count
        except psycopg.Error as e:
            logger.error(f"Failed to count alerts: {str(e)}")
            raise
        finally:
            conn.close()

    def get_unprocessed_events(self, limit: int = 10) -> List[SecurityEvent]:
        query = '''
            SELECT * FROM events 
            WHERE processed = 0
            ORDER BY timestamp ASC
            LIMIT %s
        '''
        return self._get_events_by_query(query, (limit,))

    def mark_as_processing(self, event_id: int):
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE events SET processed = 1 WHERE id = %s',
                (event_id,)
            )
            conn.commit()
        except psycopg.Error as e:
            conn.rollback()
            logger.error(f"Failed to mark event as processing: {str(e)}")
            raise
        finally:
            conn.close()

    def mark_as_processed(self, event_id: int):
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE events SET processed = 2, processed_at = %s WHERE id = %s',
                (datetime.now(), event_id)
            )
            conn.commit()
        except psycopg.Error as e:
            conn.rollback()
            logger.error(f"Failed to mark event as processed: {str(e)}")
            raise
        finally:
            conn.close()

    def mark_as_failed(self, event_id: int):
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE events SET processed = 3, processed_at = %s WHERE id = %s',
                (datetime.now(), event_id)
            )
            conn.commit()
        except psycopg.Error as e:
            conn.rollback()
            logger.error(f"Failed to mark event as failed: {str(e)}")
            raise
        finally:
            conn.close()

    def get_events_for_correlation(
        self,
        user: str,
        source: str,
        event_types: List[str],
        after: datetime,
        before: datetime,
        limit: int = 20
    ) -> List[SecurityEvent]:
        if event_types:
            placeholders = ','.join(['%s'] * len(event_types))
            query = f'''
                SELECT * FROM events 
                WHERE "user" = %s
                AND source = %s
                AND event_type IN ({placeholders})
                AND timestamp > %s
                AND timestamp < %s
                ORDER BY timestamp ASC
                LIMIT %s
            '''
            params = (user, source, *event_types, after, before, limit)
        else:
            query = '''
                SELECT * FROM events 
                WHERE "user" = %s
                AND source = %s
                AND timestamp > %s
                AND timestamp < %s
                ORDER BY timestamp ASC
                LIMIT %s
            '''
            params = (user, source, after, before, limit)
        
        return self._get_events_by_query(query, params)

    def _get_events_by_query(self, query: str, params: tuple) -> List[SecurityEvent]:
        conn = self._get_connection()
        try:
            cursor = conn.cursor(row_factory=dict_row)
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            events = []
            for row in rows:
                event = SecurityEvent(
                    id=row['id'],
                    timestamp=row['timestamp'],
                    source=row['source'],
                    event_type=row['event_type'],
                    severity=row['severity'],
                    user=row['user'],
                    action=row['action'],
                    resource=row['resource'],
                    details=row['details'] if isinstance(row['details'], dict) else json.loads(row['details'])
                )
                events.append(event)
            
            return events
        except psycopg.Error as e:
            logger.error(f"Failed to retrieve events: {str(e)}")
            raise
        finally:
            conn.close()

    def check_rate_limit(self, client_name: str, limit: int) -> tuple[bool, int]:
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            now = datetime.now()
            window_start = (now - timedelta(minutes=1))
            current_window = now.replace(second=0, microsecond=0)
            
            # Clean up old rate limit entries
            cursor.execute('DELETE FROM rate_limits WHERE window_start < %s', (window_start,))
            
            # Try to insert or update rate limit
            cursor.execute('''
                INSERT INTO rate_limits (client_name, window_start, request_count)
                VALUES (%s, %s, 1)
                ON CONFLICT(client_name, window_start)
                DO UPDATE SET request_count = rate_limits.request_count + 1
                RETURNING request_count
            ''', (client_name, current_window))
            
            request_count = cursor.fetchone()[0]
            
            if request_count > limit:
                conn.rollback()
                return False, 0
            
            conn.commit()
            remaining = max(0, limit - request_count)
            return True, remaining
        except psycopg.Error as e:
            conn.rollback()
            logger.error(f"Failed to check rate limit: {str(e)}")
            raise
        finally:
            conn.close()
    
    def get_rate_limit_status(self, client_name: str, limit: int) -> dict:
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            now = datetime.now()
            current_window = now.replace(second=0, microsecond=0)
            
            cursor.execute('''
                SELECT request_count FROM rate_limits 
                WHERE client_name = %s AND window_start = %s
            ''', (client_name, current_window))
            
            row = cursor.fetchone()
            request_count = row[0] if row else 0
            window_end = current_window + timedelta(minutes=1)
            
            return {
                "limit": limit,
                "used": request_count,
                "remaining": max(0, limit - request_count),
                "reset_at": window_end.isoformat()
            }
        except psycopg.Error as e:
            logger.error(f"Failed to get rate limit status: {str(e)}")
            raise
        finally:
            conn.close()

    def mark_as_unprocessed(self, event_id: int):
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('UPDATE events SET processed = 0 WHERE id = %s', (event_id,))
            conn.commit()
        except psycopg.Error as e:
            conn.rollback()
            logger.error(f"Failed to mark event as unprocessed: {str(e)}")
            raise
        finally:
            conn.close()

    def create_api_key(self, key_hash: str, client_name: str, rate_limit: int = 100, expires_in_days: int = 365):
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            expires_at = datetime.now(UTC) + timedelta(days=expires_in_days)
            
            cursor.execute('''
                INSERT INTO api_keys 
                (key_hash, client_name, is_active, rate_limit, expires_at)
                VALUES (%s, %s, TRUE, %s, %s)
            ''', (key_hash, client_name, rate_limit, expires_at))
            
            conn.commit()
        except psycopg.Error as e:
            conn.rollback()
            logger.error(f"Failed to create API key: {str(e)}")
            raise
        finally:
            conn.close()

    def get_api_key(self, key_hash: str) -> Optional[dict]:
        conn = self._get_connection()
        try:
            cursor = conn.cursor(row_factory=dict_row)
            cursor.execute('SELECT * FROM api_keys WHERE key_hash = %s', (key_hash,))
            row = cursor.fetchone()
            
            if row:
                return dict(row)
            return None
        except psycopg.Error as e:
            logger.error(f"Failed to retrieve API key: {str(e)}")
            raise
        finally:
            conn.close()

    def update_last_used(self, key_id: int):
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = %s',
                (key_id,)
            )
            conn.commit()
        except psycopg.Error as e:
            conn.rollback()
            logger.error(f"Failed to update last_used: {str(e)}")
            raise
        finally:
            conn.close()
    
    def count(self) -> int:
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM events')
            count = cursor.fetchone()[0]
            return count
        except psycopg.Error as e:
            logger.error(f"Failed to count events: {str(e)}")
            raise
        finally:
            conn.close()


event_store = EventStore()
