"""
Continuous Subdomain Monitoring Module
Detects new subdomains and changes over time
"""
import json
import os
import time
import hashlib
from datetime import datetime
from typing import Set, List, Dict, Optional, Tuple
from pathlib import Path

if __package__:
    from .display import ANSI
else:
    from display import ANSI


class Monitor:
    """Continuous subdomain monitoring with change detection."""

    def __init__(self,
                 domains: List[str],
                 monitor_dir: Optional[str] = None,
                 logger=None):
        """
        Initialize monitoring system.

        :param domains: List of target domains to monitor
        :param monitor_dir: Directory to store monitoring state (default: ~/.subcat/monitor/)
        :param logger: Logger instance
        """
        self.domains = [d.lower().strip() for d in domains]
        self.logger = logger

        # Setup monitoring directory
        if monitor_dir:
            self.monitor_dir = Path(monitor_dir)
        else:
            home = Path.home()
            self.monitor_dir = home / '.subcat' / 'monitor'

        self.monitor_dir.mkdir(parents=True, exist_ok=True)

    def _get_files_for_domain(self, domain: str) -> Tuple[Path, Path]:
        domain_hash = hashlib.md5(domain.encode()).hexdigest()[:8]
        state_file = self.monitor_dir / f"{domain}_{domain_hash}.json"
        history_file = self.monitor_dir / f"{domain}_{domain_hash}_history.jsonl"
        return state_file, history_file

    def _load_state(self, domain: str) -> Dict:
        """Load previous monitoring state."""
        state_file, _ = self._get_files_for_domain(domain)
        if not state_file.exists():
            return {
                'domain': domain,
                'first_seen': datetime.now().isoformat(),
                'last_check': None,
                'subdomains': [],
                'total_checks': 0
            }

        try:
            with open(state_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to load state for {domain}: {e}")
            return {
                'domain': domain,
                'first_seen': datetime.now().isoformat(),
                'last_check': None,
                'subdomains': [],
                'total_checks': 0
            }

    def _save_state(self, domain: str, state: Dict) -> None:
        """Save current monitoring state."""
        state_file, _ = self._get_files_for_domain(domain)
        try:
            with open(state_file, 'w') as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to save state for {domain}: {e}")

    def _log_changes(self, domain: str, changes: Dict) -> None:
        """Log changes to history file."""
        _, history_file = self._get_files_for_domain(domain)
        try:
            with open(history_file, 'a') as f:
                entry = {
                    'timestamp': datetime.now().isoformat(),
                    'changes': changes
                }
                f.write(json.dumps(entry) + '\n')
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to log changes for {domain}: {e}")

    def check(self, domain: str, current_subdomains: List[str]) -> Tuple[List[str], Dict]:
        """
        Check for newly discovered subdomains compared to everything seen so far.

        Passive sources are non-deterministic: a subdomain absent from a given run
        wasn't "removed", it simply wasn't returned this time. Monitoring therefore
        only ever accumulates — the known set is the union across all checks and we
        report additions only.

        :param domain: The domain being checked
        :param current_subdomains: Current list of discovered subdomains
        :return: Tuple of (new_subdomains, stats)
        """
        # Load the accumulated set of everything seen so far
        state = self._load_state(domain)
        known_subdomains = set(state.get('subdomains', []))
        current_set = set(current_subdomains)

        # Additions only, measured against the accumulated known set
        new_subdomains = sorted(current_set - known_subdomains)
        accumulated = known_subdomains | current_set

        # Calculate stats
        stats = {
            'domain': domain,
            'total_current': len(accumulated),
            'total_previous': len(known_subdomains),
            'new_count': len(new_subdomains),
            'first_seen': state.get('first_seen'),
            'last_check': state.get('last_check'),
            'current_check': datetime.now().isoformat(),
            'total_checks': state.get('total_checks', 0) + 1
        }

        # Persist the accumulated union (never shrinks)
        state['subdomains'] = sorted(accumulated)
        state['last_check'] = stats['current_check']
        state['total_checks'] = stats['total_checks']
        self._save_state(domain, state)

        # Log additions if any
        if new_subdomains:
            self._log_changes(domain, {'new': new_subdomains, 'stats': stats})
            if self.logger:
                self.logger.info(f"Found {ANSI.GREEN}{len(new_subdomains)}{ANSI.RESET} new subdomain(s) for {ANSI.RED}{domain}{ANSI.RESET}")

        return new_subdomains, stats

    def get_history(self, domain: str, limit: int = 10) -> List[Dict]:
        """
        Get monitoring history.

        :param domain: The domain to get history for
        :param limit: Maximum number of history entries to return
        :return: List of history entries
        """
        _, history_file = self._get_files_for_domain(domain)
        if not history_file.exists():
            return []

        history = []
        try:
            with open(history_file, 'r') as f:
                for line in f:
                    if line.strip():
                        history.append(json.loads(line))
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to read history for {domain}: {e}")

        # Return most recent entries
        return history[-limit:] if limit > 0 else history

    def clear_state(self, domain: str) -> bool:
        """Clear monitoring state for this domain."""
        state_file, history_file = self._get_files_for_domain(domain)
        try:
            if state_file.exists():
                state_file.unlink()
            if history_file.exists():
                history_file.unlink()

            if self.logger:
                self.logger.info(f"Cleared monitoring state for {domain}")

            return True
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to clear state for {domain}: {e}")
            return False

    def watch(self,
              scan_function,
              interval: int = 3600,
              max_iterations: Optional[int] = None,
              notify_callback: Optional[callable] = None) -> None:
        """
        Continuous monitoring mode.

        :param scan_function: Function(domain) that performs the scan and returns list of subdomains
        :param interval: Time between scans in seconds (default: 3600 = 1 hour)
        :param max_iterations: Maximum number of scans (None = infinite)
        :param notify_callback: Optional callback function(new, stats) called when new subdomains are found
        """
        iteration = 0

        if self.logger:
            self.logger.info(f"Starting monitoring for {ANSI.YELLOW}{len(self.domains)}{ANSI.RESET} domains (interval: {ANSI.YELLOW}{interval}s{ANSI.RESET})")

        try:
            while True:
                iteration += 1

                if self.logger:
                    self.logger.info(f"Monitoring check {ANSI.YELLOW}#{iteration}{ANSI.RESET} at {ANSI.BRIGHT_BLACK}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{ANSI.RESET}")

                for domain in self.domains:
                    if self.logger and len(self.domains) > 1:
                        self.logger.info(f"Checking domain: {ANSI.RED}{domain}{ANSI.RESET}")
                        
                    # Run scan
                    try:
                        current_subdomains = scan_function(domain)
                    except Exception as e:
                        if self.logger:
                            self.logger.error(f"Scan failed for {domain}: {e}")
                        current_subdomains = []

                    # Check for newly discovered subdomains
                    new_subs, stats = self.check(domain, current_subdomains)

                    # Notify if new subdomains were found
                    if new_subs and notify_callback:
                        try:
                            notify_callback(new_subs, stats)
                        except Exception as e:
                            if self.logger:
                                self.logger.error(f"Notification callback failed for {domain}: {e}")

                # Check if we should stop
                if max_iterations and iteration >= max_iterations:
                    if self.logger:
                        self.logger.info(f"Reached maximum iterations ({ANSI.YELLOW}{max_iterations}{ANSI.RESET})")
                    break

                # Wait before next scan
                if self.logger:
                    next_scan = datetime.fromtimestamp(time.time() + interval)
                    self.logger.info(f"Next scan for all domains at {ANSI.BRIGHT_BLACK}{next_scan.strftime('%Y-%m-%d %H:%M:%S')}{ANSI.RESET}")

                time.sleep(interval)

        except KeyboardInterrupt:
            raise


def format_monitoring_report(new_subdomains: List[str],
                              stats: Dict,
                              logger) -> None:
    """
    Print a monitoring report in the standard log format.

    :param new_subdomains: List of newly discovered subdomains
    :param stats: Statistics dictionary
    :param logger: Logger instance used for output
    """
    if logger is None:
        return

    domain = stats.get('domain', 'unknown')
    check = stats.get('total_checks', 0)
    total_current = stats.get('total_current', 0)

    logger.info(f"Monitoring report for {ANSI.RED}{domain}{ANSI.RESET} (check #{check})")
    logger.info(
        f"{ANSI.GREEN}{len(new_subdomains)}{ANSI.RESET} new "
        f"{ANSI.BRIGHT_BLACK}({total_current} total){ANSI.RESET}"
    )

    for subdomain in new_subdomains:
        logger.result(f"  {ANSI.GREEN}+{ANSI.RESET} {subdomain}")

    if not new_subdomains:
        logger.info("No new subdomains")
