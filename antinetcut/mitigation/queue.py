"""
Mitigation queue management
"""

import time
import json
import threading
import logging
from datetime import datetime

logger = logging.getLogger("antinetcut")

class MitigationQueue:
    def __init__(self, queue_file):
        self.queue_file = queue_file
        self.lock = threading.Lock()
        self.queue = self._load_queue()

    def _load_queue(self):
        """Load queue from file"""
        try:
            with open(self.queue_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _save_queue(self):
        """Save queue to file"""
        try:
            with open(self.queue_file, 'w') as f:
                json.dump(self.queue, f, indent=2)
        except Exception as e:
            logger.error("Failed to save queue: %s", e)

    def add(self, title, details, meta=None):
        """Add item to mitigation queue"""
        with self.lock:
            entry = {
                "id": int(time.time() * 1000),
                "title": title,
                "details": details,
                "meta": meta or {},
                "timestamp": datetime.utcnow().isoformat(),
                "approved": False
            }
            self.queue.append(entry)
            self._save_queue()
            logger.info("Queued mitigation: %s", title)

    def list(self):
        """List all queue items"""
        with self.lock:
            return self.queue.copy()

    def get(self, index):
        """Get queue item by index"""
        with self.lock:
            if 0 <= index < len(self.queue):
                return self.queue[index]
            return None

    def remove(self, index):
        """Remove item from queue by index"""
        with self.lock:
            if 0 <= index < len(self.queue):
                return self.queue.pop(index)
            return None

    def clear(self):
        """Clear all queue items"""
        with self.lock:
            self.queue = []
            self._save_queue()

    def approve(self, index):
        """Mark item as approved and return it"""
        with self.lock:
            if 0 <= index < len(self.queue):
                self.queue[index]["approved"] = True
                self.queue[index]["approved_at"] = datetime.utcnow().isoformat()
                self._save_queue()
                return self.queue[index]
            return None