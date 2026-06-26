from typing import List, Optional
from datetime import datetime
from src.models import SecurityEvent
import sqlite3
import json


class EventStore:
    def __init__(self, db_path: str = "events.db"):
        self.events: List[SecurityEvent] = []
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
    
    def add(self, event: SecurityEvent) -> str:
        event_id = self._store_to_sqlite(event_id, event)
        event.id = event_id
        return event
    
    def _store_to_sqlite(self, event: SecurityEvent):
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

    def get_alerts():
        
    
    def clear(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM events')
        conn.commit()
        conn.close()
    
    def count(self) -> int:
        return len(self.events)


event_store = EventStore()
