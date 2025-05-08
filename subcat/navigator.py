import re
import urllib.parse
import random
import time
from typing import Optional, Union, Dict, Any, Callable
from urllib3.exceptions import InsecureRequestWarning
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
if __package__:
    from .logger import Logger
else:
    from logger import Logger

# Default list of user agents for rotation.
DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:110.0) Gecko/20100101 Firefox/110.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 15_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 12; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 10; SM-A505F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/115.0.5790.98 Chrome/115.0.5790.98 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0",
    "Mozilla/5.0 (Linux; Android 9; SM-G960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15"
]


class Navigator:
    """Advanced HTTP client with comprehensive debugging, security features, rate limiting and retry logic"""

    DEFAULT_HEADERS = {
        'accept-language': 'en-GB,en;q=0.9',
        'cache-control': 'max-age=0',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'sec-ch-ua': '"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
    }

    # Rate limiting settings
    DEFAULT_RATE_LIMIT = {
        # Default rate limit: 10 requests per 1 second
        'requests': 10,
        'period': 1,
    }

    # Domain-specific rate limits
    DOMAIN_RATE_LIMITS = {
        'securitytrails.com': {'requests': 5, 'period': 60},  # 5 requests per minute
        'shodan.io': {'requests': 1, 'period': 1},            # 1 request per second
        'virustotal.com': {'requests': 4, 'period': 60},      # 4 requests per minute
        'censys.io': {'requests': 1, 'period': 1.5},          # 1 request per 1.5 seconds
        'binaryedge.io': {'requests': 10, 'period': 60},      # 10 requests per minute
        'certspotter.com': {'requests': 1, 'period': 2},      # 1 request per 2 seconds
    }

    VALID_METHODS = {'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'}

    def __init__(self,
                 debug: bool = False,
                 verify_ssl: bool = False,
                 timeout: float = 15.0,
                 user_agent: Optional[str] = None,
                 logger: Optional[Logger] = None,
                 max_retries: int = 3,
                 backoff_factor: float = 0.3,
                 rate_limit: Optional[Dict] = None):
        """
        Initialize the Navigator with advanced HTTP client features.

        :param debug: Enable debug mode for verbose logging
        :param verify_ssl: Whether to verify SSL certificates
        :param timeout: Request timeout in seconds
        :param user_agent: Custom user agent string (if None, one will be randomly selected)
        :param logger: An instance of Logger to use for logging
        :param max_retries: Maximum number of retry attempts for failed requests
        :param backoff_factor: Backoff factor for retry delay calculation
        :param rate_limit: Custom rate limit settings (overrides defaults)
        """
        self.debug = debug
        self.session = requests.Session()
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.last_response = None
        self.last_raw_content = None
        self.last_url = None
        self.request_count = 0
        self.rate_limit = rate_limit or self.DEFAULT_RATE_LIMIT
        self.last_request_time = {}  # Track last request time per domain
        self.request_counts = {}     # Track request counts per domain

        self.logger = logger

        # Configure retry strategy
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Set headers with user agent rotation
        headers = self.DEFAULT_HEADERS.copy()
        if user_agent is None:
            user_agent = random.choice(DEFAULT_USER_AGENTS)
        headers['user-agent'] = user_agent
        self.session.headers.update(headers)

        self.session.verify = verify_ssl
        if not verify_ssl:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    def _get_domain_from_url(self, url: str) -> str:
        """Extract the domain from a URL for rate limiting purposes."""
        try:
            parsed = urllib.parse.urlparse(url)
            return parsed.netloc.lower()
        except Exception:
            return "unknown"

    def _apply_rate_limit(self, domain: str) -> None:
        """Apply rate limiting for the specified domain."""
        # Get the appropriate rate limit for this domain
        rate_limit = self.rate_limit
        for domain_pattern, limit in self.DOMAIN_RATE_LIMITS.items():
            if domain_pattern in domain:
                rate_limit = limit
                break

        # Initialize tracking for this domain if not already done
        if domain not in self.last_request_time:
            self.last_request_time[domain] = time.time()
            self.request_counts[domain] = 0

        # Check if we need to apply rate limiting
        current_time = time.time()
        elapsed = current_time - self.last_request_time[domain]

        # If we've made too many requests in the period, sleep
        if self.request_counts[domain] >= rate_limit['requests']:
            if elapsed < rate_limit['period']:
                sleep_time = rate_limit['period'] - elapsed
                if self.debug or (self.logger and self.logger.level >= 2):
                    self._log_debug(f"Rate limiting for {domain}: sleeping for {sleep_time:.2f}s")
                time.sleep(sleep_time)
                # Reset counters after sleeping
                self.last_request_time[domain] = time.time()
                self.request_counts[domain] = 0
            else:
                # Period has passed, reset counters
                self.last_request_time[domain] = current_time
                self.request_counts[domain] = 0

        # Increment request count
        self.request_counts[domain] += 1

    def request(self, url: str, method: str = 'GET', response_type: str = 'text', **kwargs: Any) -> Union[
        requests.Response, str, Dict[str, Any], None]:
        """
        Make an HTTP request with rate limiting, retries, and comprehensive error handling.

        :param url: The URL to request
        :param method: HTTP method (GET, POST, etc.)
        :param response_type: Desired response format (text, json, etc.)
        :param kwargs: Additional arguments to pass to requests.request
        :return: Response in the requested format, or None on failure
        """
        method = method.upper()
        self.request_count += 1

        if method not in self.VALID_METHODS:
            self._log_error(f"Invalid method: {method}")
            return None

        # Apply rate limiting
        domain = self._get_domain_from_url(url)
        self._apply_rate_limit(domain)

        try:
            headers = kwargs.pop('headers', {})
            merged_headers = {**self.session.headers, **headers}
            allow_redirects = kwargs.pop('allow_redirects', True)

            # Log the request if in debug mode
            if self.debug or (self.logger and self.logger.level >= 2):
                self._log_debug(f"Making {method} request to {url}")

            response = self.session.request(
                method=method,
                url=url,
                headers=merged_headers,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                **kwargs
            )
            self.last_response = response
            self.last_raw_content = response.content
            self.last_url = response.url

            # Log response status if in debug mode
            if self.debug or (self.logger and self.logger.level >= 2):
                self._log_debug(f"Response status: {response.status_code}")

            # Handle rate limiting response explicitly
            if response.status_code == 429:
                retry_after = response.headers.get('Retry-After')
                if retry_after:
                    try:
                        sleep_time = float(retry_after)
                        self._log_debug(f"Rate limited by server, sleeping for {sleep_time}s")
                        time.sleep(sleep_time)
                        # Recursive call to retry after sleeping
                        return self.request(url, method, response_type, **kwargs)
                    except ValueError:
                        # If Retry-After is not a number, use our default backoff
                        self._log_debug("Invalid Retry-After header, using default backoff")

            if response_type.lower() not in ['status_code', 'full']:
                response.raise_for_status()
            return self._process_response(response, response_type)
        except requests.HTTPError as e:
            if e.response is not None:
                self.last_response = e.response
                self.last_raw_content = e.response.content
                self.last_url = e.response.url
                if response_type.lower() == 'status_code':
                    return e.response.status_code
                elif response_type.lower() == 'full':
                    return e.response
            self._log_error(f"Request failed: {e}")
            return None
        except requests.RequestException as e:
            self._log_error(f"Request failed: {e}")
            return None
        except Exception as e:
            self._log_error(f"Unexpected error: {e}")
            return None

    def _process_response(self, response: requests.Response, response_type: str) -> Union[
        requests.Response, str, Dict[str, Any], None]:
        processors = {
            'text': lambda r: r.text,
            'json': self._safe_json_parse,
            'status_code': lambda r: r.status_code,
            'headers': lambda r: dict(r.headers),
            'content': lambda r: r.content,
            'title': self._extract_title,
            'full': lambda r: r,
            'history': lambda r: [resp.url for resp in r.history]
        }
        processor = processors.get(response_type.lower())
        if not processor:
            self._log_error(f"Invalid response type: {response_type}")
            return None

        try:
            return processor(response)
        except Exception as e:
            self._log_error(f"Response processing failed: {e}")
            return None

    def _safe_json_parse(self, response: requests.Response) -> Optional[Dict]:
        try:
            content = response.text.strip()
            if not content:
                return None
            return response.json()
        except Exception as e:
            self._log_error(f"JSON parse error: {e}")
            return None

    def _extract_title(self, response: requests.Response) -> str:
        try:
            title_tag = re.search(r'<title[^>]*>(.*?)</title>', response.text, re.IGNORECASE | re.DOTALL)
            if title_tag:
                title = title_tag.group(1).strip()
                return re.sub(r'\s+', ' ', title)
            return ''
        except Exception as e:
            self._log_error(f"Title extraction failed: {e}")
            return ''

    def get_debug_info(self) -> Dict:
        if not self.last_response:
            return {}
        return {
            'status_code': self.last_response.status_code,
            'final_url': self.last_url,
            'request_headers': dict(self.last_response.request.headers),
            'response_headers': dict(self.last_response.headers),
            'redirect_history': [resp.url for resp in self.last_response.history],
            'ssl_verified': self.verify_ssl,
            'response_size': len(self.last_raw_content),
            'request_count': self.request_count,
            'partial_content': self.last_raw_content[:500].decode('utf-8', errors='replace')
        }

    def _log_error(self, message: str):
        """Log an error message."""
        if self.logger:
            self.logger.error(message)
        elif self.debug:
            print(f"\033[31m[HTTP ERROR]\033[m {message}")

    def _log_debug(self, message: str):
        """Log a debug message."""
        if self.logger:
            self.logger.debug(message)
        elif self.debug:
            print(f"\033[36m[HTTP DEBUG]\033[m {message}")

    def __enter__(self):
        """Context manager entry point."""
        return self

    def __exit__(self, *_):
        """Context manager exit point."""
        self.close()
        # We don't handle exceptions here, so return False to propagate them
        return False

    def close(self):
        """Close the session and clean up resources."""
        try:
            self.session.close()
        except Exception as e:
            if self.logger:
                self.logger.error(f"CLOSE ERROR: {e}")
            elif self.debug:
                print(f"\033[31m[CLOSE ERROR]\033[m {e}")
