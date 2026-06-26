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
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_source ON events(source)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON events(severity)')

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

        cursor.execute('CREATE INDEX IF NOT EXISTS idx_type ON alerts(type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON alerts(severity)')
        
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

    def get_alerts() -> List[Alert]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM alerts')
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        alerts = [Alert(**dict(zip(columns, row))) for row in rows]
        cursor.close()
        conn.close()
        
        return alerts
    
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
