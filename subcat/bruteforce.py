"""
Brute Force Subdomain Enumeration Module
Fast DNS-based subdomain discovery using wordlists
"""
import dns.resolver
import dns.exception
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Optional
from queue import Queue

if __package__:
    from .display import ANSI
else:
    from display import ANSI


class BruteForce:
    """High-performance DNS brute force engine."""

    # Default common subdomain wordlist (top 100)
    DEFAULT_WORDLIST = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
        'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns',
        'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2',
        'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs', 'beta',
        'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web', 'media', 'email',
        'images', 'img', 'www1', 'intranet', 'portal', 'video', 'sip', 'dns2', 'api', 'cdn',
        'stats', 'dns1', 'ns4', 'www3', 'dns', 'search', 'staging', 'server', 'mx1', 'chat',
        'wap', 'my', 'svn', 'mail1', 'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup',
        'mx2', 'lyncdiscover', 'info', 'apps', 'download', 'remote', 'db', 'forums', 'store',
        'relay', 'files', 'newsletter', 'app', 'live', 'owa', 'en', 'start', 'sms', 'office',
        'exchange', 'ipv4'
    ]

    def __init__(self,
                 domain: str,
                 wordlist: Optional[List[str]] = None,
                 wordlist_file: Optional[str] = None,
                 threads: int = 50,
                 timeout: float = 3.0,
                 retries: int = 2,
                 logger=None):
        """
        Initialize brute force engine.

        :param domain: Target domain
        :param wordlist: List of subdomain names to try
        :param wordlist_file: Path to wordlist file
        :param threads: Number of concurrent threads
        :param timeout: DNS query timeout per nameserver in seconds
        :param retries: Extra attempts on a timeout before giving up (default 2)
        :param logger: Logger instance
        """
        self.domain = domain.lower().strip()
        self.threads = threads
        self.timeout = timeout
        self.retries = max(0, retries)
        self.logger = logger
        self.found_subdomains: Set[str] = set()
        self.lock = threading.Lock()

        # Load wordlist
        if wordlist_file and os.path.exists(wordlist_file):
            self.wordlist = self._load_wordlist_file(wordlist_file)
        elif wordlist:
            self.wordlist = [w.strip().lower() for w in wordlist if w.strip()]
        else:
            self.wordlist = self.DEFAULT_WORDLIST

        # Configure DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        # lifetime is the total budget for a single resolve() call. Make it span
        # several nameservers so one slow/unresponsive resolver fails over to the
        # next instead of producing a false negative.
        self.resolver.lifetime = max(timeout * 2, timeout + 3.0)

        # Try to use fast public DNS servers
        self.resolver.nameservers = [
            '8.8.8.8',      # Google
            '8.8.4.4',      # Google
            '1.1.1.1',      # Cloudflare
            '1.0.0.1',      # Cloudflare
        ]

    def _load_wordlist_file(self, filepath: str) -> List[str]:
        """Load wordlist from file."""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                wordlist = [line.strip().lower() for line in f if line.strip()]

            if self.logger:
                self.logger.info(f"Loaded {ANSI.GREEN}{len(wordlist)}{ANSI.RESET} words from {filepath}")

            return wordlist
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to load wordlist from {filepath}: {e}")
            return self.DEFAULT_WORDLIST

    def _record_found(self, full_domain: str) -> str:
        """Record a discovered subdomain and return it."""
        with self.lock:
            self.found_subdomains.add(full_domain)
        return full_domain

    def _check_subdomain(self, subdomain: str) -> Optional[str]:
        """
        Check if subdomain exists via DNS lookup.

        Transient failures (Timeout / NoNameservers) are retried up to
        ``self.retries`` extra times so a slow resolver doesn't produce a false
        negative. Definitive answers (NXDOMAIN) short-circuit immediately.
        Returns full subdomain if it exists, None otherwise.
        """
        full_domain = f"{subdomain}.{self.domain}"

        for attempt in range(self.retries + 1):
            try:
                # Try A record lookup
                if self.resolver.resolve(full_domain, 'A'):
                    return self._record_found(full_domain)
                return None
            except dns.resolver.NXDOMAIN:
                # Definitive: the name does not exist — no point retrying.
                return None
            except dns.resolver.NoAnswer:
                # Name exists but has no A record — confirm via CNAME.
                try:
                    self.resolver.resolve(full_domain, 'CNAME')
                    return self._record_found(full_domain)
                except dns.resolver.NXDOMAIN:
                    return None
                except (dns.resolver.Timeout, dns.resolver.NoNameservers):
                    pass  # transient — fall through to retry
                except Exception:
                    return None
            except (dns.resolver.Timeout, dns.resolver.NoNameservers):
                # Transient — retry (handled by the loop).
                pass
            except dns.exception.DNSException as e:
                if self.logger:
                    self.logger.debug(f"DNS error for {full_domain}: {e}")
                return None
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"Error checking {full_domain}: {e}")
                return None

            if self.logger and attempt < self.retries:
                self.logger.debug(f"Retrying {full_domain} (attempt {attempt + 2}/{self.retries + 1})")

        if self.logger:
            self.logger.debug(f"Giving up on {full_domain} after {self.retries + 1} attempts (timeout)")
        return None

    def run(self, progress_callback=None, result_callback=None) -> List[str]:
        """
        Run brute force enumeration.

        :param progress_callback: Optional callback function(found_count, total_checked, total)
        :param result_callback: Optional callback function(subdomain) called when subdomain found
        :return: List of discovered subdomains
        """
        total = len(self.wordlist)
        checked = 0
        executor = ThreadPoolExecutor(max_workers=self.threads)

        try:
            # Submit all subdomain checks
            future_to_subdomain = {
                executor.submit(self._check_subdomain, word): word
                for word in self.wordlist
            }

            # Process results as they complete
            for future in as_completed(future_to_subdomain):
                checked += 1
                subdomain = future_to_subdomain[future]

                try:
                    result = future.result()
                    if result:
                        if self.logger:
                            self.logger.debug(f"Found: {result}")
                        # Call result callback immediately when found
                        if result_callback:
                            result_callback(result)
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"Error processing {subdomain}: {e}")

                # Progress callback
                if progress_callback and checked % 10 == 0:
                    progress_callback(len(self.found_subdomains), checked, total)

            # Final progress update
            if progress_callback:
                progress_callback(len(self.found_subdomains), checked, total)

            if self.logger:
                # debug-level: this runs while the live display is active, so the
                # user-facing completion line is printed by the CLI after the
                # display closes to avoid interleaving with the progress bar.
                self.logger.debug(f"Brute force complete: found {len(self.found_subdomains)} subdomains")

        except KeyboardInterrupt:
            # Cancel all pending futures on interrupt
            if self.logger:
                self.logger.debug("Cancelling pending DNS checks...")
            for future in future_to_subdomain:
                future.cancel()
            raise
        finally:
            # Always shutdown executor - don't wait on KeyboardInterrupt
            try:
                executor.shutdown(wait=False)
            except:
                pass

        return sorted(list(self.found_subdomains))


# Wordlist collection URLs for reference
WORDLIST_SOURCES = {
    'small': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt',
    'medium': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt',
    'large': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt',
    'bitquark': 'https://raw.githubusercontent.com/bitquark/dnspop/master/results/bitquark_20160227_subdomains_popular_1000.txt',
}
