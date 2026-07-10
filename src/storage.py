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
            "postgresql+psycopg://localhost/security_events"
        )

    def _get_connection(self):
        try:
            dsn = self.connection_string.replace('postgresql+psycopg://', 'postgresql://')
            return psycopg.connect(dsn)
        except psycopg.Error as e:
            logger.error(f"Failed to connect to PostgreSQL: {str(e)}")
            raise

    def add_security_event(self, event: SecurityEvent) -> SecurityEvent:
        event_id = self._event_to_database(event)
        event.id = event_id
        return event

    def get_event_by_id(self, event_id: str) -> Optional[SecurityEvent]:
        query = '''
                SELECT * FROM events 
                WHERE id = %s
            '''
        params = (event_id, )
        events = self._get_events_by_query(query, params)

        return events[0] if events else None

    def add_alert(self, alert: Alert) -> Alert:
        # If the alert carries a fingerprint, check whether an open alert with
        # the same fingerprint already exists. If so, increment its hit count
        # instead of creating a duplicate.
        if alert.fingerprint:
            existing = self._get_open_alert_by_fingerprint(alert.fingerprint)
            if existing:
                self._increment_alert_hit(existing["id"])
                alert.id = existing["id"]
                logger.info(
                    "Alert deduplicated (id=%s, fingerprint=%s) — hit count incremented",
                    existing["id"], alert.fingerprint[:8],
                )
                return alert

        alert_id = self._alert_to_database(alert)
        alert.id = alert_id
        return alert
    
    def _event_to_database(self, event: SecurityEvent) -> int:
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO events 
                (timestamp, source, event_type, severity, "user", action, resource, details, raw_log)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            ''', (
                event.timestamp,
                event.source,
                event.event_type,
                event.severity,
                event.user,
                event.action,
                event.resource,
                json.dumps(event.details),
                event.raw_log,
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
                (timestamp, type, severity, description, evidence, ai_reasoning,
                 confidence, recommended_actions, fingerprint, status, hit_count, last_seen_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            ''', (
                alert.timestamp,
                alert.type,
                alert.severity,
                alert.description,
                json.dumps([ev.dict() for ev in alert.evidence]),
                alert.ai_reasoning,
                alert.confidence,
                json.dumps(alert.recommended_actions),
                alert.fingerprint,
                alert.status,
                alert.hit_count,
                alert.last_seen_at,
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

    def _get_open_alert_by_fingerprint(self, fingerprint: str) -> Optional[dict]:
        conn = self._get_connection()
        try:
            cursor = conn.cursor(row_factory=dict_row)
            cursor.execute(
                "SELECT id FROM alerts WHERE fingerprint = %s AND status = 'open' LIMIT 1",
                (fingerprint,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None
        except psycopg.Error as e:
            logger.error(f"Failed to look up alert by fingerprint: {e}")
            raise
        finally:
            conn.close()

    def _increment_alert_hit(self, alert_id: int) -> None:
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE alerts SET hit_count = hit_count + 1, last_seen_at = CURRENT_TIMESTAMP WHERE id = %s",
                (alert_id,),
            )
            conn.commit()
        except psycopg.Error as e:
            conn.rollback()
            logger.error(f"Failed to increment alert hit count: {e}")
            raise
        finally:
            conn.close()

    def update_alert_status(self, alert_id: int, status: str) -> bool:
        """Update the lifecycle status of an alert. Returns False if not found."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE alerts SET status = %s WHERE id = %s",
                (status, alert_id),
            )
            conn.commit()
            return cursor.rowcount > 0
        except psycopg.Error as e:
            conn.rollback()
            logger.error(f"Failed to update alert status: {e}")
            raise
        finally:
            conn.close()

    def get_alerts(
        self,
        limit: int,
        offset: int,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Alert]:
        conn = self._get_connection()
        try:
            cursor = conn.cursor(row_factory=dict_row)
            conditions = []
            params: list = []
            if severity:
                conditions.append("severity = %s")
                params.append(severity)
            if status:
                conditions.append("status = %s")
                params.append(status)
            where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
            cursor.execute(
                f"SELECT * FROM alerts {where} ORDER BY timestamp DESC LIMIT %s OFFSET %s",
                [*params, limit, offset],
            )
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
                    recommended_actions=row['recommended_actions'],
                    fingerprint=row.get('fingerprint'),
                    status=row.get('status', 'open'),
                    hit_count=row.get('hit_count', 1),
                    last_seen_at=row.get('last_seen_at'),
                )
                alerts.append(alert)
            return alerts
        except psycopg.Error as e:
            logger.error(f"Failed to retrieve alerts: {str(e)}")
            raise
        finally:
            conn.close()

    def count_alerts(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> int:
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            conditions = []
            params: list = []
            if severity:
                conditions.append("severity = %s")
                params.append(severity)
            if status:
                conditions.append("status = %s")
                params.append(status)
            where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
            cursor.execute(f"SELECT COUNT(*) FROM alerts {where}", params)
            return cursor.fetchone()[0]
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

    def get_events_by_ip(
        self,
        ip: str,
        after: datetime,
        before: datetime,
        limit: int = 100,
    ) -> List[SecurityEvent]:
        """
        Return all events whose details->>'ip' matches `ip` within the given
        time window, across ALL sources and users.  Used by IP-context rules
        (e.g. IPSweepRule) to detect coordinated multi-target attacks.
        """
        query = """
            SELECT * FROM events
            WHERE details->>'ip' = %s
            AND timestamp > %s
            AND timestamp <= %s
            ORDER BY timestamp ASC
            LIMIT %s
        """
        return self._get_events_by_query(query, (ip, after, before, limit))

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
                    details=row['details'] if isinstance(row['details'], dict) else json.loads(row['details']),
                    raw_log=row.get('raw_log'),
                )
                events.append(event)
            
            return events
        except psycopg.Error as e:
            logger.error(f"Failed to retrieve events: {str(e)}")
            raise
        finally:
            conn.close()

    def get_user_by_username(self, username: str) -> Optional[dict]:
        conn = self._get_connection()
        try:
            cursor = conn.cursor(row_factory=dict_row)
            cursor.execute(
                "SELECT * FROM users WHERE username = %s AND is_active = TRUE LIMIT 1",
                (username,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None
        except psycopg.Error as e:
            logger.error(f"Failed to get user by username: {e}")
            raise
        finally:
            conn.close()

    def create_user_account(
        self,
        username: str,
        email: Optional[str],
        password_hash: str,
        is_admin: bool = False,
    ) -> dict:
        conn = self._get_connection()
        try:
            cursor = conn.cursor(row_factory=dict_row)
            cursor.execute(
                """
                INSERT INTO users (username, email, password_hash, is_admin)
                VALUES (%s, %s, %s, %s)
                RETURNING id, username, email, is_admin, created_at
                """,
                (username, email, password_hash, is_admin),
            )
            row = cursor.fetchone()
            conn.commit()
            return dict(row)
        except psycopg.Error as e:
            conn.rollback()
            logger.error(f"Failed to create user account: {e}")
            raise
        finally:
            conn.close()

    def user_exists(self, username: str) -> bool:
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM users WHERE username = %s LIMIT 1", (username,))
            return cursor.fetchone() is not None
        except psycopg.Error as e:
            logger.error(f"Failed to check user existence: {e}")
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

    def get_api_key_by_client(self, client_name: str) -> Optional[dict]:
        conn = self._get_connection()
        try:
            cursor = conn.cursor(row_factory=dict_row)
            cursor.execute(
                'SELECT * FROM api_keys WHERE client_name = %s LIMIT 1',
                (client_name,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None
        except psycopg.Error as e:
            logger.error(f"Failed to retrieve API key by client: {str(e)}")
            raise
        finally:
            conn.close()

    def update_last_used(self, key_hash: str):
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE key_hash = %s',
                (key_hash,)
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
