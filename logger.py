import sys
import threading
from datetime import datetime
from typing import Optional


class Logger:
    def __init__(self, level: int = 1, silent: bool = False, color: bool = True):
        """
        :param level: Verbosity level (0=Silent, 1=Info, 2=Debug, 3=Verbose)
        """
        self.level = level
        self.silent = silent
        self.print_lock = threading.Lock()
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
                'bright_red': '\033[91m',  # Light red
                'bright_green': '\033[92m',
                'bright_yellow': '\033[93m',
                'bright_blue': '\033[94m',
                'bright_magenta': '\033[95m',
                'bright_cyan': '\033[96m',  # Light cyan
                'bright_white': '\033[97m',
                'bold': '\033[1m'
            }
        else:
            self.colors = {
                'reset': '\033[m',
                'black': '\033[m',
                'red': '\033[m',
                'green': '\033[m',
                'yellow': '\033[m',
                'blue': '\033[m',
                'magenta': '\033[m',
                'cyan': '\033[m',
                'white': '\033[m',
                'bright_black': '\033[m',
                'bright_red': '\033[m',
                'bright_green': '\033[m',
                'bright_yellow': '\033[m',
                'bright_blue': '\033[m',
                'bright_magenta': '\033[m',
                'bright_cyan': '\033[m',
                'bright_white': '\033[m',
                'bold': '\033[m'
            }

    def _format(self, level_label: str, color: str, message: str) -> str:
        now = datetime.now().strftime("%H:%M:%S")
        return f"[{self.colors['bright_blue']}{now}{self.colors['reset']}][{color}{level_label}{self.colors['reset']}]: {message}"

    def _log(self, level_label: str, color: str, message: str, newlines: int):
        with self.print_lock:
            sys.stderr.write('\r' + ' ' * 80 + '\r')
            sys.stderr.flush()
            print(self._format(level_label, color, message) + "\n" * newlines)

    def info(self, message: str, newlines: int = 0, extra: dict = None):
        if self.level >= 1 and not self.silent:
            if extra:
                message = message.format(**extra)
            self._log("INF", self.colors['green'], message, newlines)

    def debug(self, message: str, newlines: int = 0, extra: dict = None):
        if self.level >= 3 and not self.silent:
            if extra:
                message = message.format(**extra)
            self._log("DBG", self.colors['yellow'], message, newlines)

    def verbose(self, message: str, newlines: int = 0, extra: dict = None):
        if self.level >= 4 and not self.silent:
            if extra:
                message = message.format(**extra)
            self._log("VRB", self.colors['blue'], message, newlines)

    def warn(self, message: str, newlines: int = 0, extra: dict = None):
        if self.level >= 2 and not self.silent:
            if extra:
                message = message.format(**extra)
            self._log("WRN", self.colors['red'], message, newlines)

    def error(self, message: str, newlines: int = 0, extra: dict = None):
        if self.level >= 2 and not self.silent:
            if extra:
                message = message.format(**extra)
            self._log("ERR", self.colors['red'], message, newlines)

    def stdout(self, message: str, spinner: str, processed: str, total: str):
        with self.print_lock:
            if not self.silent:
                now = datetime.now().strftime("%H:%M:%S")
                sys.stdout.write(
                    f"\r[{self.colors['bright_blue']}{now}{self.colors['reset']}][{self.colors['bright_magenta']}{processed}{self.colors['reset']}/{self.colors['bold']}{self.colors['yellow']}{total}{self.colors['reset']}]{self.colors['reset']}[{self.colors['green']}{spinner}{self.colors['reset']}]: {message}")
                # sys.stdout.flush()

    def result(self, message: str, newlines: int = 1, extra: dict = None):
        if extra:
            message = message.format(**extra)
        sys.stdout.write(message + "\n" * newlines)

