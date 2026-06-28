"""
Optimized Display System for SubCat - No Flicker, Fast Performance.

Features:
- Smooth updates (no flickering)
- Smart rendering (only update when changed)
- Optimized performance
- Better terminal control
"""
import sys
import time
import threading
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from collections import deque


# ANSI Control and Color Codes
class ANSI:
    """ANSI escape codes for terminal control."""
    # Cursor control
    CURSOR_UP = '\033[{}A'
    CURSOR_DOWN = '\033[{}B'
    CURSOR_FORWARD = '\033[{}C'
    CURSOR_BACK = '\033[{}D'
    CURSOR_POS = '\033[{};{}H'
    CURSOR_SAVE = '\033[s'
    CURSOR_RESTORE = '\033[u'
    CURSOR_HIDE = '\033[?25l'
    CURSOR_SHOW = '\033[?25h'

    # Clear
    CLEAR_LINE = '\033[2K'
    CLEAR_TO_END = '\033[0J'
    CLEAR_SCREEN = '\033[2J'

    # Colors
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    # Standard colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    # Bright colors
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'

    @classmethod
    def disable_colors(cls):
        """Disable all color codes (for --no-colors option)."""
        cls.RESET = ''
        cls.BOLD = ''
        cls.DIM = ''
        cls.BLACK = ''
        cls.RED = ''
        cls.GREEN = ''
        cls.YELLOW = ''
        cls.BLUE = ''
        cls.MAGENTA = ''
        cls.CYAN = ''
        cls.WHITE = ''
        cls.BRIGHT_BLACK = ''
        cls.BRIGHT_RED = ''
        cls.BRIGHT_GREEN = ''
        cls.BRIGHT_YELLOW = ''
        cls.BRIGHT_BLUE = ''
        cls.BRIGHT_MAGENTA = ''
        cls.BRIGHT_CYAN = ''
        cls.BRIGHT_WHITE = ''


# Simple spinners (fewer frames = smoother)
SPINNERS = {
    'dots': ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'],
    'line': ['-', '\\', '|', '/'],
    'simple': ['●', '◉', '○', '◉'],
    'arrow': ['←', '↑', '→', '↓'],
    'box': ['◰', '◳', '◲', '◱'],
}


# Rich Progress Display (optional, requires Rich library)
try:
    from rich.console import Console
    from rich.progress import (
        Progress,
        TextColumn,
        BarColumn,
        TaskProgressColumn,
        TimeElapsedColumn,
        MofNCompleteColumn,
        ProgressColumn
    )
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


if RICH_AVAILABLE:
    class TimestampColumn(ProgressColumn):
        """Custom column to display current timestamp with spinner."""

        SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

        def __init__(self):
            super().__init__()
            self._frame_index = 0

        def render(self, task):
            """Render the timestamp with spinner or INF."""
            current_time = time.strftime("%H:%M:%S")

            # Check if scan is complete
            is_complete = task.finished or "complete" in str(task.description).lower()

            if is_complete:
                status_symbol = "INF"
            else:
                # Show spinner while scanning
                status_symbol = self.SPINNER_FRAMES[self._frame_index % len(self.SPINNER_FRAMES)]
                self._frame_index += 1

            timestamp_text = Text()
            timestamp_text.append("[", style="bright_black")
            timestamp_text.append(current_time, style="cyan")
            timestamp_text.append("]", style="bright_black")
            timestamp_text.append("[", style="bright_black")
            timestamp_text.append(status_symbol, style="green")
            timestamp_text.append("]:", style="bright_black")
            return timestamp_text


    class ProgressDisplay:
        """NetExec-style display with progress bar and real-time output."""

        def __init__(self, domain: str, total_modules: int, show_modules: bool = False, show_alive_stats: bool = False):
            """Initialize progress display."""
            self.domain = domain
            self.total_modules = total_modules
            self.show_modules = show_modules
            self.show_alive_stats = show_alive_stats
            self.start_time = time.time()
            self.modules_completed = 0
            self.total_to_process = 0  # Total domains found by modules (to be processed)
            self.total_processed = 0  # Domains processed so far
            self.total_alive = 0  # Track alive/up subdomains (HTTP 200-299)
            self.active_module: Optional[str] = None
            self.modules: Dict[str, Dict] = {}
            self._lock = threading.Lock()
            self._active = False
            self.console = Console()
            self.last_subdomain_time = time.time()  # Track subdomain discovery rate

            # Single progress instance with both tasks for proper coordination
            self.progress = Progress(
                TimestampColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(complete_style="green", finished_style="bold green"),
                TaskProgressColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                console=self.console,
                transient=False,
                refresh_per_second=12
            )
            self.task_id = None  # Module progress task
            self.subdomain_task_id = None  # Subdomain progress task
            self.module_progress_active = True  # Track if module progress is visible

        def __enter__(self):
            self.start()
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            self.stop()
            return False

        def start(self):
            with self._lock:
                if self._active:
                    return
                self._active = True

            # Add both tasks to single progress instance
            self.task_id = self.progress.add_task(
                f"[cyan]Modules",
                total=self.total_modules
            )
            self.subdomain_task_id = self.progress.add_task(
                f"[yellow]Subdomains",
                total=0,
                completed=0
            )
            self.progress.start()

        def stop(self):
            with self._lock:
                if not self._active:
                    return
                # Finalize subdomain progress before stopping.
                if self.subdomain_task_id is not None:
                    if self.total_processed > 0:
                        if self.show_alive_stats:
                            elapsed = time.time() - self.start_time
                            avg_rate = self.total_processed / elapsed if elapsed > 0 else 0
                            alive_pct = int((self.total_alive / self.total_processed * 100)) if self.total_processed > 0 else 0
                            description = f"[bold yellow]Subdomains [dim]({avg_rate:.1f}/s avg)[/dim] [yellow]({self.total_alive}/{self.total_processed}[green] alive / {alive_pct}%[/green])[/yellow]"
                        else:
                            description = f"[bold yellow]Subdomains"

                        # The scan is finished: everything that was going to be
                        # processed has been. total_to_process counts raw hits
                        # (with cross-module duplicates) while total_processed
                        # counts the deduplicated subdomains actually handled, so
                        # anchor the bar to total_processed to land cleanly at
                        # 100% instead of a stale partial value.
                        self.progress.update(
                            self.subdomain_task_id,
                            total=self.total_processed,
                            completed=self.total_processed,
                            description=description
                        )
                    else:
                        # Nothing was found/processed — drop the empty bar instead
                        # of leaving a stuck "0/0" spinner behind.
                        try:
                            self.progress.remove_task(self.subdomain_task_id)
                        except Exception:
                            pass
                        self.subdomain_task_id = None
                self._active = False
            self.progress.stop()

        def _get_subdomain_rate_text(self) -> str:
            """Calculate subdomain discovery rate."""
            elapsed = time.time() - self.start_time
            if elapsed < 1:
                return ""
            rate = self.total_found / elapsed
            if rate < 1:
                return f" ({rate:.1f}/min)" if rate > 0 else ""
            elif rate < 60:
                return f" ({rate:.1f}/s)"
            else:
                rate_per_min = rate * 60
                return f" ({rate_per_min:.0f}/min)"

        def add_module(self, module_name: str):
            with self._lock:
                self.modules[module_name] = {
                    'status': 'pending',
                    'results': 0,
                    'start_time': None,
                    'end_time': None
                }

        def module_started(self, module_name: str):
            with self._lock:
                if module_name in self.modules:
                    self.modules[module_name]['status'] = 'running'
                    self.modules[module_name]['start_time'] = time.time()
                    self.active_module = module_name
                if self.task_id is not None and self.module_progress_active:
                    # Update module progress description with current module
                    self.progress.update(
                        self.task_id,
                        description=f"[cyan]Modules [yellow]({module_name})"
                    )

        def module_completed(self, module_name: str, results_count: int):
            with self._lock:
                if module_name in self.modules:
                    self.modules[module_name]['status'] = 'completed'
                    self.modules[module_name]['end_time'] = time.time()
                    self.modules[module_name]['results'] = results_count
                self.modules_completed += 1
                # Add to total domains to process
                self.total_to_process += results_count
                # Update subdomain progress total
                if self.subdomain_task_id is not None:
                    self.progress.update(
                        self.subdomain_task_id,
                        total=self.total_to_process
                    )
                if self.task_id is not None and self.module_progress_active:
                    # Advance module progress
                    self.progress.update(self.task_id, advance=1)

                    if self.modules_completed >= self.total_modules:
                        # All modules complete - remove module progress bar
                        self.progress.remove_task(self.task_id)
                        self.module_progress_active = False
                    # Note: Don't reset description - keep showing last module until next starts

        def module_failed(self, module_name: str, error: str):
            with self._lock:
                if module_name in self.modules:
                    self.modules[module_name]['status'] = 'failed'
                    self.modules[module_name]['end_time'] = time.time()
                    self.modules[module_name]['error'] = error
                self.modules_completed += 1
                if self.task_id is not None and self.module_progress_active:
                    # Advance module progress even on failure
                    self.progress.update(self.task_id, advance=1)

                    # Check if all modules done (including this failed one)
                    if self.modules_completed >= self.total_modules:
                        # Remove module progress bar
                        self.progress.remove_task(self.task_id)
                        self.module_progress_active = False
                    # Note: Don't reset description - keep showing last module until next starts

        def add_result(self, subdomain: str, module: str, protocol: Optional[str] = None,
                       status: Optional[int] = None, title: Optional[str] = None,
                       ip: Optional[str] = None, technologies: Optional[list] = None, skip_print: bool = False,
                       is_alive: Optional[bool] = None):
            with self._lock:
                self.total_processed += 1

                # Check if subdomain is alive
                # Use explicit is_alive if provided, otherwise infer from status/title/ip
                if is_alive is None:
                    is_alive = False
                    if status is not None:
                        # Any status code means the subdomain is responding/alive
                        is_alive = True
                    elif title or ip:
                        # If no status code but has title/IP, it responded
                        is_alive = True

                if is_alive:
                    self.total_alive += 1

                if module in self.modules:
                    self.modules[module]['results'] += 1

                # Update subdomain progress bar
                if self.subdomain_task_id is not None:
                    # Show rate and alive stats only when probing for alive domains
                    if self.show_alive_stats:
                        elapsed = time.time() - self.start_time
                        rate = self.total_processed / elapsed if elapsed >= 1 else 0
                        rate_text = f" [dim]({rate:.1f}/s)[/dim]" if rate > 0 and elapsed >= 1 else ""
                        alive_text = f" [yellow]({self.total_alive}/{self.total_processed} alive)[/yellow]"
                        description = f"[yellow]Subdomains{rate_text}{alive_text}"
                    else:
                        description = f"[yellow]Subdomains"

                    # Update progress as domains are processed
                    self.progress.update(
                        self.subdomain_task_id,
                        completed=self.total_processed,
                        description=description
                    )

            # Skip printing if requested (count only, used for --up flag with dead domains)
            if skip_print:
                return

            # Format output with protocol if available (no colors on URL)
            if protocol:
                url_text = f"{protocol}://{subdomain}"
                display_text = f"{url_text:<50}"
            else:
                display_text = f"{subdomain:<50}"

            # Add status code if available (httpx-style coloring with brackets)
            if status is not None:
                status_color = "white"
                try:
                    code = int(status)
                    if 200 <= code < 300:
                        status_color = "green"
                    elif 300 <= code < 400:
                        status_color = "yellow"
                    elif 400 <= code < 500:
                        status_color = "red"
                    elif code >= 500:
                        status_color = "bold yellow"
                    else:
                        status_color = "yellow"
                except:
                    status_color = "red"
                display_text += f" [{status_color}][{status}][/{status_color}]"

            # Add title if available (cyan brackets - httpx style)
            if title:
                title_truncated = title[:30]
                display_text += f" [cyan][{title_truncated}][/cyan]"

            # Add IP if available (cyan brackets)
            if ip:
                display_text += f" [cyan][{ip}][/cyan]"

            # Add technologies if available (magenta brackets - httpx style)
            if technologies:
                techs = ",".join(technologies)
                display_text += f" [magenta][{techs}][/magenta]"

            # Add module if show_modules is enabled (dim gray parentheses)
            if self.show_modules:
                display_text += f" [dim]({module})[/dim]"

            self.progress.console.print(display_text, highlight=False)

        def print_final_summary(self):
            pass


@dataclass
class ModuleStatus:
    """Status of a module."""
    name: str
    status: str = 'pending'
    found_count: int = 0
    duration: float = 0.0
    start_time: Optional[float] = None
    error: Optional[str] = None


class OptimizedDisplay:
    """
    Optimized live display - smooth, fast, no flicker.

    Improvements over original:
    - 200ms updates instead of 50ms (4x slower updates)
    - Smart rendering (only update when state changes)
    - Better cursor control (no screen clearing)
    - Buffered output (reduces flicker)
    """

    def __init__(self,
                 domain: str,
                 total_modules: int,
                 enable_animations: bool = True,
                 spinner_style: str = 'simple',
                 max_recent_results: int = 5,
                 update_interval: float = 0.067,  # ~67ms (3x faster)
                 print_results_realtime: bool = True,  # Print domains as found
                 show_modules: bool = False):  # Show module names with results
        """
        Initialize optimized display.

        :param domain: Target domain
        :param total_modules: Total number of modules
        :param enable_animations: Enable spinner animations
        :param spinner_style: Spinner style ('simple', 'dots', 'line', 'arrow', 'box')
        :param max_recent_results: Maximum recent results to show (default 5)
        :param update_interval: Update interval in seconds (default 0.067)
        :param print_results_realtime: Print discovered domains in real-time (default True)
        :param show_modules: Show module names with results (default False)
        """
        self.domain = domain
        self.total_modules = total_modules
        self.enable_animations = enable_animations
        self.spinner_chars = SPINNERS.get(spinner_style, SPINNERS['simple'])
        self.max_recent_results = max_recent_results
        self.update_interval = update_interval
        self.print_results_realtime = print_results_realtime
        self.show_modules = show_modules

        # State
        self.modules: Dict[str, ModuleStatus] = {}
        self.total_to_process = 0  # Total domains found by modules (to be processed)
        self.total_processed = 0  # Domains processed so far
        self.start_time = time.time()
        self.recent_results: deque = deque(maxlen=max_recent_results)

        # Control
        self._running = False
        self._update_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._spinner_index = 0

        # Optimization: track if state changed
        self._state_changed = True
        self._last_output = ""

        # Terminal
        self._terminal_width = self._get_terminal_width()
        self._display_active = False

    def _get_terminal_width(self) -> int:
        """Get terminal width."""
        try:
            import shutil
            return shutil.get_terminal_size().columns
        except Exception:
            return 80

    def start(self):
        """Start the live display."""
        with self._lock:
            if self._running:
                return

            self._running = True
            self._display_active = True

            # Hide cursor for smoother display
            sys.stderr.write(ANSI.CURSOR_HIDE)
            sys.stderr.flush()

            self._update_thread = threading.Thread(
                target=self._update_loop,
                daemon=True
            )
            self._update_thread.start()

    def stop(self):
        """Stop the live display."""
        with self._lock:
            if not self._running:
                return

            self._running = False
            self._display_active = False

            if self._update_thread:
                self._update_thread.join(timeout=1.0)

        # Show cursor again
        sys.stderr.write(ANSI.CURSOR_SHOW)
        sys.stderr.write('\n')
        sys.stderr.flush()

    def add_module(self, module_name: str):
        """Add a module to track."""
        with self._lock:
            self.modules[module_name] = ModuleStatus(name=module_name)
            self._state_changed = True

    def module_started(self, module_name: str):
        """Mark module as started."""
        with self._lock:
            if module_name in self.modules:
                self.modules[module_name].status = 'running'
                self.modules[module_name].start_time = time.time()
                self._state_changed = True

    def module_completed(self, module_name: str, count: int):
        """Mark module as completed."""
        with self._lock:
            if module_name in self.modules:
                module = self.modules[module_name]
                module.status = 'completed'
                module.found_count = count
                if module.start_time:
                    module.duration = time.time() - module.start_time
                self._state_changed = True
            # Add to total domains to process
            self.total_to_process += count

    def module_failed(self, module_name: str, error: str):
        """Mark module as failed."""
        with self._lock:
            if module_name in self.modules:
                module = self.modules[module_name]
                module.status = 'failed'
                module.error = error
                self._state_changed = True

    def add_result(self, subdomain: str, module: str, protocol: Optional[str] = None,
                   status: Optional[int] = None, title: Optional[str] = None,
                   ip: Optional[str] = None, technologies: Optional[list] = None, skip_print: bool = False,
                   is_alive: Optional[bool] = None):
        """Add a found subdomain."""
        with self._lock:
            self.total_processed += 1
            self.recent_results.append((subdomain, module, time.time()))
            self._state_changed = True

            # Skip printing if requested (count only, used for --up flag with dead domains)
            if skip_print:
                return

            # Print in real-time if enabled
            if self.print_results_realtime and self._display_active:
                # Clear the current status line on stderr first
                sys.stderr.write('\r' + ' ' * self._terminal_width + '\r')
                sys.stderr.flush()

                # Format output with protocol if available (no colors on URL)
                if protocol:
                    url_part = f"{protocol}://{subdomain}"
                else:
                    url_part = subdomain

                # Pad URL to 50 characters for alignment
                display_text = f"{url_part:<50}"

                # Add status code if available (httpx-style coloring with brackets)
                if status is not None:
                    status_color = ANSI.RESET
                    try:
                        code = int(status)
                        if 200 <= code < 300:
                            status_color = ANSI.GREEN
                        elif 300 <= code < 400:
                            status_color = ANSI.YELLOW
                        elif 400 <= code < 500:
                            status_color = ANSI.RED
                        elif code >= 500:
                            status_color = ANSI.BOLD + ANSI.YELLOW
                        else:
                            status_color = ANSI.YELLOW
                    except:
                        status_color = ANSI.RED
                    display_text += f" {status_color}[{status}]{ANSI.RESET}"

                # Add title if available (cyan brackets - httpx style)
                if title:
                    title_truncated = title[:30]
                    display_text += f" {ANSI.CYAN}[{title_truncated}]{ANSI.RESET}"

                # Add IP if available (cyan brackets)
                if ip:
                    display_text += f" {ANSI.CYAN}[{ip}]{ANSI.RESET}"

                # Add technologies if available (magenta brackets - httpx style)
                if technologies:
                    techs = ",".join(technologies)
                    display_text += f" {ANSI.MAGENTA}[{techs}]{ANSI.RESET}"

                # Add module if show_modules is enabled (dim gray parentheses)
                if self.show_modules:
                    display_text += f" {ANSI.DIM}({module}){ANSI.RESET}"

                print(display_text, flush=True)

                # Status line will be re-rendered by update loop

    def _update_loop(self):
        """Background thread that updates display (optimized)."""
        while self._running:
            try:
                # Only render if state changed or animation needs update
                if self._state_changed or self.enable_animations:
                    self._render_display()
                    self._state_changed = False

                time.sleep(self.update_interval)
            except Exception:
                pass

    def _render_display(self):
        """Render the display (optimized version)."""
        with self._lock:
            output = self._build_output()

            # Only update if output actually changed
            if output == self._last_output and self.enable_animations:
                # Just update spinner
                self._spinner_index = (self._spinner_index + 1) % len(self.spinner_chars)
                return

            self._last_output = output

            # Move cursor to beginning and write
            sys.stderr.write('\r')
            sys.stderr.write(output)
            sys.stderr.flush()

            # Update spinner
            if self.enable_animations:
                self._spinner_index = (self._spinner_index + 1) % len(self.spinner_chars)

    def _build_output(self) -> str:
        """Build compact output string with dual progress tracking."""
        elapsed = time.time() - self.start_time
        spinner = self.spinner_chars[self._spinner_index] if self.enable_animations else '●'

        # Get current timestamp
        current_time = time.strftime("%H:%M:%S")

        # Count status
        completed = sum(1 for m in self.modules.values() if m.status == 'completed')
        running = sum(1 for m in self.modules.values() if m.status == 'running')
        failed = sum(1 for m in self.modules.values() if m.status == 'failed')

        # Build output with timestamp prefix
        prefix = f"{ANSI.BRIGHT_BLACK}[{current_time}]{ANSI.RESET}{ANSI.CYAN}[INF]{ANSI.RESET}: "

        # Calculate module progress percentage
        module_progress = (completed / self.total_modules * 100) if self.total_modules > 0 else 0

        # Calculate subdomain processing rate
        rate = self.total_processed / elapsed if elapsed >= 1 else 0
        rate_text = f" {ANSI.DIM}({rate:.1f}/s){ANSI.RESET}" if rate > 0 and elapsed >= 1 else ""

        # Compact single line output with dual progress
        parts = []
        parts.append(f"{ANSI.BOLD}{ANSI.CYAN}{spinner}{ANSI.RESET}")
        parts.append(f"{ANSI.BRIGHT_YELLOW}{self.domain}{ANSI.RESET}")

        # Dual Progress: Modules and Subdomains with processing progress
        parts.append(f"{ANSI.BRIGHT_WHITE}Modules:{ANSI.RESET} {ANSI.BRIGHT_GREEN}{completed}{ANSI.RESET}/{ANSI.BRIGHT_WHITE}{self.total_modules}{ANSI.RESET} {ANSI.BRIGHT_BLACK}({int(module_progress)}%){ANSI.RESET}")

        # Show subdomain progress as processed/total if total is known, otherwise just count
        if self.total_to_process > 0:
            subdomain_progress = (self.total_processed / self.total_to_process * 100) if self.total_to_process > 0 else 0
            parts.append(f"{ANSI.BRIGHT_WHITE}Subdomains:{ANSI.RESET} {ANSI.BRIGHT_MAGENTA}{self.total_processed}{ANSI.RESET}/{ANSI.BRIGHT_WHITE}{self.total_to_process}{ANSI.RESET} {ANSI.BRIGHT_BLACK}({int(subdomain_progress)}%){ANSI.RESET}{rate_text}")
        else:
            parts.append(f"{ANSI.BRIGHT_WHITE}Subdomains:{ANSI.RESET} {ANSI.BRIGHT_MAGENTA}{self.total_processed}{ANSI.RESET}{rate_text}")

        # Status indicators (compact)
        status_parts = []
        if running > 0:
            status_parts.append(f"{ANSI.BRIGHT_YELLOW}⟳{running}{ANSI.RESET}")
        if failed > 0:
            status_parts.append(f"{ANSI.BRIGHT_RED}✗{failed}{ANSI.RESET}")
        if status_parts:
            parts.append(" ".join(status_parts))

        parts.append(f"{ANSI.BRIGHT_BLACK}{self._format_time(elapsed)}{ANSI.RESET}")

        return prefix + " │ ".join(parts)

    def _format_time(self, seconds: float) -> str:
        """Format time duration (compact)."""
        if seconds < 60:
            return f"{int(seconds)}s"
        else:
            minutes = int(seconds // 60)
            secs = int(seconds % 60)
            return f"{minutes}m{secs}s"

    def print_final_summary(self):
        """Print final summary after scan completion."""
        self.stop()

    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
        return False


class SimpleDisplay:
    """Simple display without live updates (fallback)."""

    def __init__(self, domain: str):
        """Initialize simple display."""
        self.domain = domain
        self.total_to_process = 0
        self.total_processed = 0
        self.start_time = time.time()

    def start(self):
        """Start display."""
        print(f"{ANSI.BOLD}{ANSI.CYAN}SubCat{ANSI.RESET} scanning {ANSI.BRIGHT_YELLOW}{self.domain}{ANSI.RESET}\n")

    def stop(self):
        """Stop display."""
        pass

    def add_module(self, module_name: str):
        """Add module (no-op)."""
        pass

    def module_started(self, module_name: str):
        """Module started."""
        print(f"  {ANSI.BRIGHT_BLACK}[{module_name}]{ANSI.RESET} Starting...")

    def module_completed(self, module_name: str, count: int):
        """Module completed."""
        self.total_to_process += count
        print(f"  {ANSI.BRIGHT_GREEN}✓{ANSI.RESET} {module_name} found {ANSI.BRIGHT_MAGENTA}{count}{ANSI.RESET}")

    def module_failed(self, module_name: str, error: str):
        """Module failed."""
        print(f"  {ANSI.BRIGHT_RED}✗{ANSI.RESET} {module_name} failed")

    def add_result(self, subdomain: str, module: str, protocol: Optional[str] = None,
                   status: Optional[int] = None, title: Optional[str] = None,
                   ip: Optional[str] = None, technologies: Optional[list] = None, skip_print: bool = False,
                   is_alive: Optional[bool] = None):
        """Add result."""
        self.total_processed += 1
        # Don't print each result in simple mode to avoid spam

    def print_final_summary(self):
        """Print final summary."""
        pass

    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
        return False


class SilentDisplay:
    """Silent display - no output at all (for --silent mode)."""

    def __init__(self, domain: str, show_modules: bool = False):
        """Initialize silent display."""
        self.domain = domain
        self.total_to_process = 0
        self.total_processed = 0
        self.show_modules = show_modules

    def start(self):
        """Start display (no-op)."""
        pass

    def stop(self):
        """Stop display (no-op)."""
        pass

    def add_module(self, module_name: str):
        """Add module (no-op)."""
        pass

    def module_started(self, module_name: str):
        """Module started (no-op)."""
        pass

    def module_completed(self, module_name: str, count: int):
        """Module completed (no-op)."""
        self.total_to_process += count

    def module_failed(self, module_name: str, error: str):
        """Module failed (no-op)."""
        pass

    def add_result(self, subdomain: str, module: str, protocol: Optional[str] = None,
                   status: Optional[int] = None, title: Optional[str] = None,
                   ip: Optional[str] = None, technologies: Optional[list] = None, skip_print: bool = False,
                   is_alive: Optional[bool] = None):
        """Add result - print subdomain with all info in silent mode."""
        self.total_processed += 1

        # Skip printing if requested (count only)
        if skip_print:
            return
        # In silent mode, still print the actual results, just no progress info
        # Format with protocol if available (httpx-style)
        display_text = f"{protocol}://{subdomain}" if protocol else subdomain

        # Add status code if available (with brackets)
        if status is not None:
            display_text += f" [{status}]"

        # Add title if available (with brackets)
        if title:
            display_text += f" [{title[:30]}]"

        # Add IP if available (with brackets)
        if ip:
            display_text += f" [{ip}]"

        # Add technologies if available (with brackets)
        if technologies:
            techs = ",".join(technologies)
            display_text += f" [{techs}]"

        # Add module if show_modules is enabled (parentheses)
        if self.show_modules:
            display_text += f" ({module})"

        print(display_text)

    def print_final_summary(self):
        """Print final summary (no-op)."""
        pass

    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
        return False


def create_display(domain: str, total_modules: int, use_simple: bool = False, use_optimized: bool = False, print_results_realtime: bool = True, colors_enabled: bool = True, silent: bool = False, show_modules: bool = False, show_alive_stats: bool = False):
    """
    Create appropriate display based on environment.

    :param domain: Target domain
    :param total_modules: Total number of modules
    :param use_simple: Force simple display
    :param use_optimized: Use optimized single-line display (instead of progress bar)
    :param print_results_realtime: Print discovered domains in real-time (default True)
    :param colors_enabled: Whether colors are enabled (False for --no-colors)
    :param silent: Silent mode - no progress output at all (False for --silent)
    :param show_modules: Show module names with results (False for --show-modules)
    :param show_alive_stats: Show alive domain statistics (only when probing for alive domains)
    :return: Display instance
    """
    # Silent mode: no progress output at all
    if silent:
        return SilentDisplay(domain, show_modules=show_modules)

    # Check if we're in a TTY
    is_tty = sys.stderr.isatty()

    # Force optimized display if colors are disabled (Rich can't disable colors properly)
    if not colors_enabled:
        use_optimized = True

    # Simple display for non-TTY or explicit request
    if use_simple or not is_tty:
        return SimpleDisplay(domain)

    # Optimized display if explicitly requested
    if use_optimized:
        return OptimizedDisplay(
            domain,
            total_modules,
            enable_animations=True,
            spinner_style='simple',
            update_interval=0.067,
            print_results_realtime=print_results_realtime,
            show_modules=show_modules
        )

    # Default: Progress display (nxc-style) - the cool one!
    if RICH_AVAILABLE:
        return ProgressDisplay(domain, total_modules, show_modules=show_modules, show_alive_stats=show_alive_stats)
    else:
        # Fallback to optimized if Rich not available
        print("Warning: Rich not available, falling back to optimized display")
        print("Install with: pip install rich")
        return OptimizedDisplay(
            domain,
            total_modules,
            enable_animations=True,
            spinner_style='simple',
            update_interval=0.067,
            print_results_realtime=print_results_realtime,
            show_modules=show_modules
        )


# Backward compatibility
LiveDisplay = OptimizedDisplay
Colors = ANSI
