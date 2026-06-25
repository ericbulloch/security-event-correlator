from typing import List, Optional
from datetime import datetime
from src.models import SecurityEvent
import sqlite3
import json

class EventStore:
    def __init__(self, use_sqlite: bool = False, db_path: str = "events.db"):
        self.events: List[SecurityEvent] = []
        self.use_sqlite = use_sqlite
        self.db_path = db_path
        if use_sqlite:
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
        
        conn.commit()
        conn.close()
    
    def add(self, event: SecurityEvent) -> str:
        event_id = f"evt_{len(self.events)}_{int(datetime.now().timestamp())}"
        self.events.append(event)
        if self.use_sqlite:
            self._store_to_sqlite(event_id, event)
        return event_id
    
    def _store_to_sqlite(self, event_id: str, event: SecurityEvent):
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
        
        conn.commit()
        conn.close()
    
    def clear(self):
        self.events = []
        if self.use_sqlite:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM events')
            conn.commit()
            conn.close()
    
    def count(self) -> int:
        return len(self.events)


event_store = EventStore(use_sqlite=True)
