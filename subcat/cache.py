"""
Cache module for SubCat using SQLite.
Provides fast caching functionality to improve performance and reduce API calls.
"""
import os
import json
import time
import sqlite3
import hashlib
from typing import Any, Optional
from threading import Lock


class Cache:
    """
    SQLite-based cache for storing API responses and other data.
    Much faster than JSON file cache for large datasets.
    """

    def __init__(self, cache_dir: str = None, ttl: int = 86400):
        """
        Initialize the SQLite cache.

        :param cache_dir: Directory to store cache database (default: ~/.subcat/cache)
        :param ttl: Time-to-live for cache entries in seconds (default: 24 hours)
        """
        if cache_dir is None:
            home = os.path.expanduser("~")
            cache_dir = os.path.join(home, ".subcat", "cache")

        self.cache_dir = cache_dir
        self.ttl = ttl
        self._lock = Lock()

        # Create cache directory if it doesn't exist
        os.makedirs(self.cache_dir, exist_ok=True)

        # SQLite database path
        self.db_path = os.path.join(self.cache_dir, "subcat_cache.db")

        # Initialize database
        self._init_db()

    def _init_db(self):
        """Initialize the SQLite database with cache table."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    timestamp REAL NOT NULL
                )
            """)
            # Create index on timestamp for faster expiration cleanup
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp ON cache(timestamp)
            """)
            conn.commit()

    def _get_cache_key(self, key: str) -> str:
        """
        Generate a cache key from the input string.

        :param key: Input string to hash
        :return: Hashed cache key
        """
        return hashlib.md5(key.encode('utf-8')).hexdigest()

    def get(self, key: str) -> Optional[Any]:
        """
        Get a value from the cache.

        :param key: Cache key
        :return: Cached value or None if not found or expired
        """
        cache_key = self._get_cache_key(key)

        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT value, timestamp FROM cache WHERE key = ?",
                        (cache_key,)
                    )
                    result = cursor.fetchone()

                    if result is None:
                        return None

                    value_json, timestamp = result

                    # Check if the cache entry has expired
                    if time.time() - timestamp > self.ttl:
                        # Cache expired, remove it
                        cursor.execute("DELETE FROM cache WHERE key = ?", (cache_key,))
                        conn.commit()
                        return None

                    # Deserialize the value
                    return json.loads(value_json)

            except (sqlite3.Error, json.JSONDecodeError):
                return None

    def set(self, key: str, value: Any) -> bool:
        """
        Set a value in the cache.

        :param key: Cache key
        :param value: Value to cache (must be JSON-serializable)
        :return: True if successful, False otherwise
        """
        cache_key = self._get_cache_key(key)

        with self._lock:
            try:
                # Serialize the value
                value_json = json.dumps(value)

                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT OR REPLACE INTO cache (key, value, timestamp) VALUES (?, ?, ?)",
                        (cache_key, value_json, time.time())
                    )
                    conn.commit()

                return True
            except (sqlite3.Error, TypeError, json.JSONEncodeError):
                return False

    def delete(self, key: str) -> bool:
        """
        Delete a value from the cache.

        :param key: Cache key
        :return: True if successful, False otherwise
        """
        cache_key = self._get_cache_key(key)

        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM cache WHERE key = ?", (cache_key,))
                    conn.commit()
                    return cursor.rowcount > 0
            except sqlite3.Error:
                return False

    def clear(self) -> bool:
        """
        Clear all cache entries.

        :return: True if successful, False otherwise
        """
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM cache")
                    conn.commit()
                return True
            except sqlite3.Error:
                return False

    def clear_expired(self) -> int:
        """
        Clear expired cache entries.

        :return: Number of entries cleared
        """
        with self._lock:
            try:
                cutoff_time = time.time() - self.ttl

                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "DELETE FROM cache WHERE timestamp < ?",
                        (cutoff_time,)
                    )
                    conn.commit()
                    return cursor.rowcount
            except sqlite3.Error:
                return 0

    def get_stats(self) -> dict:
        """
        Get cache statistics.

        :return: Dictionary with cache stats
        """
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()

                    # Total entries
                    cursor.execute("SELECT COUNT(*) FROM cache")
                    total = cursor.fetchone()[0]

                    # Expired entries
                    cutoff_time = time.time() - self.ttl
                    cursor.execute("SELECT COUNT(*) FROM cache WHERE timestamp < ?", (cutoff_time,))
                    expired = cursor.fetchone()[0]

                    # Database size
                    db_size = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0

                    return {
                        'total_entries': total,
                        'expired_entries': expired,
                        'active_entries': total - expired,
                        'db_size_bytes': db_size,
                        'db_size_mb': round(db_size / (1024 * 1024), 2)
                    }
            except (sqlite3.Error, OSError):
                return {
                    'total_entries': 0,
                    'expired_entries': 0,
                    'active_entries': 0,
                    'db_size_bytes': 0,
                    'db_size_mb': 0
                }
