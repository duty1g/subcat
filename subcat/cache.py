"""
Cache module for SubCat.
Provides caching functionality to improve performance and reduce API calls.
"""
import os
import json
import time
import hashlib
from typing import Any, Dict, Optional, Union, List

class Cache:
    """
    A simple file-based cache for storing API responses and other data.
    """
    
    def __init__(self, cache_dir: str = None, ttl: int = 86400):
        """
        Initialize the cache.
        
        :param cache_dir: Directory to store cache files (default: ~/.subcat/cache)
        :param ttl: Time-to-live for cache entries in seconds (default: 24 hours)
        """
        if cache_dir is None:
            home = os.path.expanduser("~")
            cache_dir = os.path.join(home, ".subcat", "cache")
        
        self.cache_dir = cache_dir
        self.ttl = ttl
        
        # Create cache directory if it doesn't exist
        os.makedirs(self.cache_dir, exist_ok=True)
    
    def _get_cache_key(self, key: str) -> str:
        """
        Generate a cache key from the input string.
        
        :param key: Input string to hash
        :return: Hashed cache key
        """
        return hashlib.md5(key.encode('utf-8')).hexdigest()
    
    def _get_cache_path(self, key: str) -> str:
        """
        Get the file path for a cache key.
        
        :param key: Cache key
        :return: File path
        """
        cache_key = self._get_cache_key(key)
        return os.path.join(self.cache_dir, f"{cache_key}.json")
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get a value from the cache.
        
        :param key: Cache key
        :return: Cached value or None if not found or expired
        """
        cache_path = self._get_cache_path(key)
        
        if not os.path.exists(cache_path):
            return None
        
        try:
            with open(cache_path, 'r') as f:
                cache_data = json.load(f)
            
            # Check if the cache entry has expired
            if time.time() - cache_data['timestamp'] > self.ttl:
                # Cache expired, remove it
                os.remove(cache_path)
                return None
            
            return cache_data['value']
        except (json.JSONDecodeError, KeyError, IOError):
            # If there's any error reading the cache, return None
            return None
    
    def set(self, key: str, value: Any) -> bool:
        """
        Set a value in the cache.
        
        :param key: Cache key
        :param value: Value to cache
        :return: True if successful, False otherwise
        """
        cache_path = self._get_cache_path(key)
        
        try:
            cache_data = {
                'timestamp': time.time(),
                'value': value
            }
            
            with open(cache_path, 'w') as f:
                json.dump(cache_data, f)
            
            return True
        except (IOError, TypeError):
            # If there's any error writing to the cache, return False
            return False
    
    def delete(self, key: str) -> bool:
        """
        Delete a value from the cache.
        
        :param key: Cache key
        :return: True if successful, False otherwise
        """
        cache_path = self._get_cache_path(key)
        
        if not os.path.exists(cache_path):
            return False
        
        try:
            os.remove(cache_path)
            return True
        except IOError:
            return False
    
    def clear(self) -> bool:
        """
        Clear all cache entries.
        
        :return: True if successful, False otherwise
        """
        try:
            for filename in os.listdir(self.cache_dir):
                if filename.endswith('.json'):
                    os.remove(os.path.join(self.cache_dir, filename))
            return True
        except IOError:
            return False
    
    def clear_expired(self) -> int:
        """
        Clear expired cache entries.
        
        :return: Number of entries cleared
        """
        cleared_count = 0
        
        try:
            for filename in os.listdir(self.cache_dir):
                if not filename.endswith('.json'):
                    continue
                
                cache_path = os.path.join(self.cache_dir, filename)
                
                try:
                    with open(cache_path, 'r') as f:
                        cache_data = json.load(f)
                    
                    # Check if the cache entry has expired
                    if time.time() - cache_data['timestamp'] > self.ttl:
                        os.remove(cache_path)
                        cleared_count += 1
                except (json.JSONDecodeError, KeyError, IOError):
                    # If there's any error reading the cache, remove it
                    try:
                        os.remove(cache_path)
                        cleared_count += 1
                    except IOError:
                        pass
            
            return cleared_count
        except IOError:
            return cleared_count
