import sys
import os
import threading
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Any, Dict
from collections import deque


class Logger:
    """Enhanced logger with file output, rotation, and structured logging support."""

    def __init__(
        self,
        level: int = 1,
        silent: bool = False,
        color: bool = True,
        log_file: Optional[str] = None,
        max_file_size: int = 10 * 1024 * 1024,  # 10MB default
        backup_count: int = 3,
        json_format: bool = False,
        buffer_size: int = 100
    ):
        """
        :param level: Verbosity level (0=Silent, 1=Info, 2=Debug, 3=Verbose, 4=Trace)
        :param silent: Suppress all console output
        :param color: Enable ANSI color codes
        :param log_file: Path to log file (None = console only)
        :param max_file_size: Maximum log file size before rotation (bytes)
        :param backup_count: Number of backup files to keep
        :param json_format: Use JSON format for file logging
        :param buffer_size: Number of log entries to buffer before flush
        """
        self.level = level
        self.silent = silent
        self.print_lock = threading.Lock()
        self.log_file = log_file
        self.max_file_size = max_file_size
        self.backup_count = backup_count
        self.json_format = json_format
        self.buffer_size = buffer_size
        self.buffer = deque(maxlen=buffer_size)
        self._file_handle = None

        # Initialize log file if specified
        if self.log_file:
            self._init_log_file()
        self.color = color
        if color:
            self.colors = {
                'reset': '\033[0m',
                'black': '\033[30m',
                'red': '\033[31m',
                'green': '\033[32m',
                'yellow': '\033[33m',
                'blue': '\033[34m',
                'magenta': '\033[35m',
                'cyan': '\033[36m',
                'white': '\033[37m',
                'bright_black': '\033[90m',
                'bright_red': '\033[91m',
                'bright_green': '\033[92m',
                'bright_yellow': '\033[93m',
                'bright_blue': '\033[94m',
                'bright_magenta': '\033[95m',
                'bright_cyan': '\033[96m',
                'bright_white': '\033[97m',
                'bold': '\033[1m'
            }
        else:
            self.colors = {key: '' for key in [
                'reset', 'black', 'red', 'green', 'yellow', 'blue', 'magenta',
                'cyan', 'white', 'bright_black', 'bright_red', 'bright_green',
                'bright_yellow', 'bright_blue', 'bright_magenta', 'bright_cyan',
                'bright_white', 'bold'
            ]}

    def _init_log_file(self):
        """Initialize the log file and create parent directories if needed."""
        try:
            log_path = Path(self.log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            # Check if rotation is needed
            if log_path.exists() and log_path.stat().st_size >= self.max_file_size:
                self._rotate_logs()

            self._file_handle = open(self.log_file, 'a', encoding='utf-8', buffering=1)
        except Exception as e:
            sys.stderr.write(f"Failed to initialize log file {self.log_file}: {e}\n")
            self.log_file = None

    def _rotate_logs(self):
        """Rotate log files when size limit is reached."""
        try:
            log_path = Path(self.log_file)

            # Remove oldest backup if we're at the limit
            oldest_backup = log_path.with_suffix(f"{log_path.suffix}.{self.backup_count}")
            if oldest_backup.exists():
                oldest_backup.unlink()

            # Rotate existing backups
            for i in range(self.backup_count - 1, 0, -1):
                old_backup = log_path.with_suffix(f"{log_path.suffix}.{i}")
                new_backup = log_path.with_suffix(f"{log_path.suffix}.{i + 1}")
                if old_backup.exists():
                    old_backup.rename(new_backup)

            # Move current log to .1
            if log_path.exists():
                log_path.rename(log_path.with_suffix(f"{log_path.suffix}.1"))
        except Exception as e:
            sys.stderr.write(f"Failed to rotate logs: {e}\n")

    def _write_to_file(self, level: str, message: str, extra: Optional[Dict[str, Any]] = None):
        """Write log entry to file."""
        if not self.log_file or not self._file_handle:
            return

        try:
            timestamp = datetime.now().isoformat()

            if self.json_format:
                log_entry = {
                    'timestamp': timestamp,
                    'level': level,
                    'message': message
                }
                if extra:
                    log_entry['extra'] = extra
                self._file_handle.write(json.dumps(log_entry) + '\n')
            else:
                log_line = f"[{timestamp}][{level}]: {message}\n"
                self._file_handle.write(log_line)

            # Check if rotation is needed
            if os.path.getsize(self.log_file) >= self.max_file_size:
                self._file_handle.close()
                self._rotate_logs()
                self._file_handle = open(self.log_file, 'a', encoding='utf-8', buffering=1)
        except Exception as e:
            sys.stderr.write(f"Failed to write to log file: {e}\n")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensure file is closed."""
        self.close()
        return False

    def close(self):
        """Close the log file handle."""
        if self._file_handle:
            try:
                self._file_handle.close()
            except Exception:
                pass
            self._file_handle = None

    def _format(self, level_label: str, color: str, message: str) -> str:
        """Format a log message for console output."""
        now = datetime.now().strftime("%H:%M:%S")
        return f"{self.colors['bright_black']}[{self.colors['cyan']}{now}{self.colors['bright_black']}][{color}{level_label}{self.colors['bright_black']}]:{self.colors['reset']} {message}"

    def _log(self, level_label: str, color: str, message: str, newlines: int, extra: Optional[Dict[str, Any]] = None):
        """Log a message to console and/or file."""
        # Write to file first
        if self.log_file:
            self._write_to_file(level_label, message, extra)

        # Then write to console
        if not self.silent:
            with self.print_lock:
                sys.stderr.write('\r' + ' ' * 80 + '\r')
                sys.stderr.flush()
                print(self._format(level_label, color, message) + "\n" * newlines)

    def trace(self, message: str, newlines: int = 0, extra: Optional[Dict[str, Any]] = None):
        """Log trace-level message (level 5 - most verbose)."""
        if self.level >= 5:
            formatted_msg = message.format(**extra) if extra else message
            self._log("TRC", self.colors['bright_black'], formatted_msg, newlines, extra)

    def debug(self, message: str, newlines: int = 0, extra: Optional[Dict[str, Any]] = None):
        """Log debug-level message (level 3)."""
        if self.level >= 3:
            formatted_msg = message.format(**extra) if extra else message
            self._log("DBG", self.colors['yellow'], formatted_msg, newlines, extra)

    def verbose(self, message: str, newlines: int = 0, extra: Optional[Dict[str, Any]] = None):
        """Log verbose-level message (level 4)."""
        if self.level >= 4:
            formatted_msg = message.format(**extra) if extra else message
            self._log("VRB", self.colors['blue'], formatted_msg, newlines, extra)

    def info(self, message: str, newlines: int = 0, extra: Optional[Dict[str, Any]] = None):
        """Log info-level message (level 1 - default)."""
        if self.level >= 1:
            formatted_msg = message.format(**extra) if extra else message
            self._log("INF", self.colors['green'], formatted_msg, newlines, extra)

    def success(self, message: str, newlines: int = 0, extra: Optional[Dict[str, Any]] = None):
        """Log a success message with checkmark symbol (level 1)."""
        if self.level >= 1:
            formatted_msg = message.format(**extra) if extra else message
            self._log("✓", self.colors['green'], formatted_msg, newlines, extra)

    def warn(self, message: str, newlines: int = 0, extra: Optional[Dict[str, Any]] = None):
        """Log warning message (level 2)."""
        if self.level >= 2:
            formatted_msg = message.format(**extra) if extra else message
            self._log("WRN", self.colors['yellow'], formatted_msg, newlines, extra)

    def error(self, message: str, newlines: int = 0, extra: Optional[Dict[str, Any]] = None):
        """Log error message (level 2)."""
        if self.level >= 2:
            formatted_msg = message.format(**extra) if extra else message
            self._log("ERR", self.colors['red'], formatted_msg, newlines, extra)

    def critical(self, message: str, newlines: int = 0, extra: Optional[Dict[str, Any]] = None):
        """Log critical error message (always shown unless silent=True)."""
        formatted_msg = message.format(**extra) if extra else message
        self._log("CRT", self.colors['bright_red'], formatted_msg, newlines, extra)

    def stdout(self, message: str, spinner: str, processed: str, total: str):
        """Write progress output to stdout (not logged to file)."""
        with self.print_lock:
            if not self.silent:
                now = datetime.now().strftime("%H:%M:%S")
                sys.stdout.write(
                    f"\r[{self.colors['bright_blue']}{now}{self.colors['reset']}][{self.colors['bright_magenta']}{processed}{self.colors['reset']}/{self.colors['bold']}{self.colors['yellow']}{total}{self.colors['reset']}]{self.colors['reset']}[{self.colors['green']}{spinner}{self.colors['reset']}]: {message}")

    def result(self, message: str, newlines: int = 1, extra: Optional[Dict[str, Any]] = None):
        """Write result output to stdout (not logged to file)."""
        if extra:
            message = message.format(**extra)
        sys.stdout.write(message + "\n" * newlines)

    def flush(self):
        """Flush any buffered log entries."""
        if self._file_handle:
            try:
                self._file_handle.flush()
            except Exception:
                pass

    def set_level(self, level: int):
        """Change the logging level at runtime."""
        self.level = level

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the logger."""
        stats = {
            'level': self.level,
            'silent': self.silent,
            'color': self.color,
            'file_logging': self.log_file is not None,
            'json_format': self.json_format
        }

        if self.log_file and os.path.exists(self.log_file):
            stats['log_file'] = self.log_file
            stats['log_file_size'] = os.path.getsize(self.log_file)
            stats['log_file_size_mb'] = round(os.path.getsize(self.log_file) / (1024 * 1024), 2)

        return stats

