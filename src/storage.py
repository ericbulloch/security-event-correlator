from typing import List, Optional
from datetime import datetime
import sqlite3
import json

from src.models import Alert, SecurityEvent


class EventStore:
    def __init__(self, db_path: str = "events.db"):
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                user TEXT,
                action TEXT NOT NULL,
                resource TEXT,
                details TEXT NOT NULL,
                processed INTEGER DEFAULT 0,  -- 0=unprocessed, 1=processing, 2=processed
                processed_at TEXT,
                correlation_id TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_source ON events(source)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_processed ON events(processed)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_correlation_id ON events(correlation_id)')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence TEXT NOT NULL,
                ai_reasoning TEXT NOT NULL,
                confidence FLOAT NOT NULL,
                recommended_actions TEXT NOT NULL
            )
        ''')

        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)')
        
        conn.commit()
        conn.close()
    
    def add_security_event(self, event: SecurityEvent) -> SecurityEvent:
        event_id = self._event_to_sqlite(event)
        event.id = event_id
        return event

    def add_alert(self, alert: Alert) -> Alert:
        alert_id = self._alert_to_sqlite(alert)
        alert.id = alert_id
        return alert
    
    def _event_to_sqlite(self, event: SecurityEvent) -> int:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO events 
            (timestamp, source, event_type, severity, user, action, resource, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event.timestamp.isoformat(),
            event.source,
            event.event_type,
            event.severity,
            event.user,
            event.action,
            event.resource,
            json.dumps(event.details)
        ))
        inserted_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return inserted_id

    def _alert_to_sqlite(self, alert: Alert) -> int:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO alerts 
            (timestamp, type, severity, description, evidence, ai_reasoning, confidence, recommended_actions)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert.timestamp.isoformat(),
            alert.type,
            alert.severity,
            alert.description,
            json.dumps(alert.evidence),
            alert.ai_reasoning,
            alert.confidence,
            json.dumps(alert.recommended_actions)
        ))
        inserted_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return inserted_id

    def get_alerts(self) -> List[Alert]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM alerts')
        rows = cursor.fetchall()
        column_names = [desc[0] for desc in cursor.description]
        alerts = []
        for row in rows:
            row_dict = dict(zip(column_names, row))
            row_dict['evidence'] = json.loads(row_dict['evidence']) if isinstance(row_dict['evidence'], str) else []
            row_dict['recommended_actions'] = json.loads(row_dict['recommended_actions']) if isinstance(row_dict['recommended_actions'], str) else []
            alert = Alert(**row_dict)
            alerts.append(alert)
        conn.close()
        
        return alerts

    def get_unprocessed_events(self, limit: int = 10) -> List[SecurityEvent]:
        query = '''
            SELECT * FROM events 
            WHERE processed = 0
            ORDER BY timestamp ASC
            LIMIT ?
        '''
        
        return self._get_events_by_query(query, (limit,))

    def mark_as_processing(self, event_id: int):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('UPDATE events SET processed = 1 WHERE id = ?', (event_id,))
        conn.commit()
        conn.close()

    def mark_as_processed(self, event_id: int):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE events SET processed = 2, processed_at = ? WHERE id = ?
        ''', (datetime.now().isoformat(), event_id))
        conn.commit()
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
        placeholders = ','.join('?' * len(event_types))
        query = f'''
            SELECT * FROM events 
            WHERE user = ?
            AND source = ?
            AND event_type IN ({placeholders})
            AND timestamp > ?
            AND timestamp < ?
            ORDER BY timestamp ASC
            LIMIT ?
        '''
        params = (user, source, *event_types, after.isoformat(), before.isoformat(), limit)
        
        return self._get_events_by_query(query, params)

    def _get_events_by_query(self, query: str, params: tuple) -> List[SecurityEvent]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        column_names = [desc[0] for desc in cursor.description]
        events = []
        for row in rows:
            row_dict = dict(zip(column_names, row))
            event = SecurityEvent(
                id=row_dict['id'],
                timestamp=datetime.fromisoformat(row_dict['timestamp']),
                source=row_dict['source'],
                event_type=row_dict['event_type'],
                severity=row_dict['severity'],
                user=row_dict['user'],
                action=row_dict['action'],
                resource=row_dict['resource'],
                details=json.loads(row_dict['details']) if isinstance(row_dict['details'], str) else row_dict['details']
            )
            events.append(event)
        conn.close()
        
        return events
    
    def clear(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM events')
        cursor.execute('DELETE FROM alerts')
        conn.commit()
        conn.close()
    
    def count(self) -> int:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM events')
        num = cursor.fetchone()[0]
        conn.close()

        return num


event_store = EventStore()
