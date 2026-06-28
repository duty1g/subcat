import re
import urllib.parse
import random
import time
import asyncio
from typing import Optional, Union, Dict, Any
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

# Optional async support
try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

# Optional real-browser navigation support (Playwright Chromium). This is a
# third navigation mode alongside the requests (sync) and aiohttp (async)
# clients, used by the screenshot gallery and deep technology detection.
try:
    import playwright.async_api  # noqa: F401
    PLAYWRIGHT_AVAILABLE = True
except Exception:
    PLAYWRIGHT_AVAILABLE = False

# In-page scripts (run via page.evaluate) that collect detection evidence.
# Collect all <meta> name/property/http-equiv -> content values.
_META_JS = """() => {
  const out = {};
  document.querySelectorAll('meta').forEach(m => {
    const k = (m.getAttribute('name') || m.getAttribute('property') ||
               m.getAttribute('http-equiv') || '').toLowerCase();
    const c = m.getAttribute('content');
    if (k && c != null) { (out[k] = out[k] || []).push(c); }
  });
  return out;
}"""

# Probe a list of window.* dotted paths; return {path: stringValue} for those
# that exist (Wappalyzer `js` fingerprints).
_JS_PROBE = """(paths) => {
  const out = {};
  for (const p of paths) {
    try {
      let v = window;
      for (const part of p.split('.')) {
        if (v == null) { v = undefined; break; }
        v = v[part];
      }
      if (v !== undefined && v !== null) {
        const t = typeof v;
        out[p] = (t === 'string' || t === 'number' || t === 'boolean') ? String(v) : '';
      }
    } catch (e) {}
  }
  return out;
}"""

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
    """
    Advanced HTTP client with comprehensive debugging, security features, rate limiting and retry logic.
    Uses standard requests + urllib3 for reliability and performance.
    """

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
        'securitytrails.com': {'requests': 5, 'period': 10},  # 5 requests per 10 seconds
        'shodan.io': {'requests': 1, 'period': 1},            # 1 request per second
        'virustotal.com': {'requests': 4, 'period': 10},      # 4 requests per 10 seconds
        'censys.io': {'requests': 1, 'period': 1.5},          # 1 request per 1.5 seconds
        'binaryedge.io': {'requests': 10, 'period': 10},      # 10 requests per 10 seconds
        'certspotter.com': {'requests': 1, 'period': 2},      # 1 request per 2 seconds
    }

    VALID_METHODS = {'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'}

    def __init__(self,
                 debug: bool = False,
                 verify_ssl: bool = False,
                 timeout: float = 15.0,
                 user_agent: Optional[str] = None,
                 logger: Optional[Logger] = None,
                 max_retries: int = 0,
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
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.last_response = None
        self.last_raw_content = None
        self.last_url = None
        self.request_count = 0
        self.rate_limit = rate_limit or self.DEFAULT_RATE_LIMIT
        self.last_request_time = {}  # Track last request time per domain
        self.request_counts = {}     # Track request counts per domain

        # Playwright browser navigation (lazy). One persistent browser per
        # Navigator, shared across browse() calls; started/closed explicitly.
        self._pw = None
        self._browser = None

        self.logger = logger

        # Set headers with user agent rotation BEFORE creating session
        headers = self.DEFAULT_HEADERS.copy()
        if user_agent is None:
            user_agent = random.choice(DEFAULT_USER_AGENTS)
        headers['user-agent'] = user_agent

        # Create session
        self.session = requests.Session()

        # Configure retry strategy with urllib3
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]
        )

        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,
            pool_maxsize=10
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Apply headers to session
        self.session.headers.update(headers)

        # Configure SSL verification
        self.session.verify = verify_ssl
        if not verify_ssl:
            # Disable warnings for unverified HTTPS requests
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

    # Async context manager support
    async def __aenter__(self):
        """Async context manager entry - creates aiohttp session."""
        if not AIOHTTP_AVAILABLE:
            raise ImportError("aiohttp required for async. Install: pip install aiohttp")

        # Create aiohttp session
        connector = aiohttp.TCPConnector(
            ssl=self.verify_ssl,
            limit=100,
            limit_per_host=10,
            ttl_dns_cache=300
        )
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        self.aio_session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=dict(self.session.headers)
        )
        return self

    async def __aexit__(self, *_):
        """Async context manager exit - closes aiohttp session."""
        if hasattr(self, 'aio_session') and self.aio_session:
            await self.aio_session.close()
        return False

    async def arequest(self, url: str, method: str = 'GET', response_type: str = 'text', **kwargs):
        """
        Async HTTP request using aiohttp.

        :param url: URL to request
        :param method: HTTP method
        :param response_type: 'text', 'json', or 'bytes'
        :param kwargs: Additional aiohttp arguments
        :return: Response data or None
        """
        if not hasattr(self, 'aio_session'):
            raise RuntimeError("Use 'async with Navigator()' for async requests")

        # Apply rate limiting
        domain = self._get_domain_from_url(url)
        await self._async_apply_rate_limit(domain)

        # Merge headers
        headers = kwargs.pop('headers', {})
        merged_headers = {**dict(self.session.headers), **headers}

        try:
            async with self.aio_session.request(
                method,
                url,
                headers=merged_headers,
                **kwargs
            ) as response:
                if response.status == 429:
                    retry_after = response.headers.get('Retry-After', '5')
                    await asyncio.sleep(float(retry_after))
                    return await self.arequest(url, method, response_type, **kwargs)

                if response_type == 'json':
                    return await response.json()
                elif response_type == 'bytes':
                    return await response.read()
                else:
                    return await response.text()
        except Exception as e:
            if self.logger:
                self.logger.debug(f"Async request failed: {e}")
            return None

    async def _async_apply_rate_limit(self, domain: str):
        """Async rate limiting."""
        rate_limit = self.rate_limit
        for pattern, limit in self.DOMAIN_RATE_LIMITS.items():
            if pattern in domain:
                rate_limit = limit
                break

        if domain not in self.last_request_time:
            self.last_request_time[domain] = time.time()
            self.request_counts[domain] = 0

        current_time = time.time()
        elapsed = current_time - self.last_request_time[domain]

        if self.request_counts[domain] >= rate_limit['requests']:
            if elapsed < rate_limit['period']:
                sleep_time = rate_limit['period'] - elapsed
                await asyncio.sleep(sleep_time)
                self.last_request_time[domain] = time.time()
                self.request_counts[domain] = 0
            else:
                self.last_request_time[domain] = current_time
                self.request_counts[domain] = 0

        self.request_counts[domain] += 1

    # ---- Playwright browser navigation (third navigation mode) -----------

    @staticmethod
    def have_playwright() -> bool:
        """True if the playwright package is importable."""
        return PLAYWRIGHT_AVAILABLE

    async def start_browser(self, headless: bool = True):
        """Launch the persistent Chromium browser (idempotent)."""
        if self._browser is not None:
            return self._browser
        from playwright.async_api import async_playwright
        self._pw = await async_playwright().start()
        self._browser = await self._pw.chromium.launch(
            headless=headless,
            args=['--no-sandbox', '--disable-dev-shm-usage', '--ignore-certificate-errors'],
        )
        return self._browser

    async def close_browser(self):
        """Close the persistent browser and Playwright driver (idempotent)."""
        try:
            if self._browser is not None:
                await self._browser.close()
        except Exception:
            pass
        finally:
            self._browser = None
        try:
            if self._pw is not None:
                await self._pw.stop()
        except Exception:
            pass
        finally:
            self._pw = None

    async def browse(self, url: str, *, screenshot_path: str = None,
                     full_page: bool = False, js_paths=None,
                     viewport=(1280, 800), wait_ms: int = 600,
                     user_agent: str = None) -> Dict[str, Any]:
        """
        Navigate to ``url`` with a real browser (Playwright Chromium) and collect
        rich page evidence: rendered HTML, response headers, cookies, real script
        URLs, meta tags and ``window.*`` JS globals. Optionally writes a PNG to
        ``screenshot_path``.

        Returns an evidence dict consumable by both the screenshot index and
        ``Detector.detect_rich`` (keys: url/final_url/status/title/server/headers/
        html/scriptSrc/meta/cookies/js/screenshot/error/timestamp).
        """
        ev: Dict[str, Any] = {
            'url': url, 'final_url': None, 'status': None, 'title': None,
            'server': None, 'headers': {}, 'html': '', 'scriptSrc': [],
            'meta': {}, 'cookies': {}, 'js': {}, 'screenshot': None,
            'error': None, 'timestamp': time.time(),
        }
        if self._browser is None:
            await self.start_browser()

        context = None
        page = None
        try:
            context = await self._browser.new_context(
                viewport={'width': viewport[0], 'height': viewport[1]},
                ignore_https_errors=True,
                user_agent=user_agent or self.session.headers.get('user-agent'),
            )
            page = await context.new_page()
            resp = await page.goto(url, wait_until='domcontentloaded',
                                   timeout=int(self.timeout * 1000))

            # Give late content a brief moment to paint.
            try:
                await page.wait_for_timeout(wait_ms)
            except Exception:
                pass

            ev['final_url'] = page.url
            resp_headers = {}
            if resp is not None:
                ev['status'] = resp.status
                try:
                    resp_headers = await resp.all_headers()
                except Exception:
                    resp_headers = {}
            ev['headers'] = resp_headers
            ev['server'] = resp_headers.get('server')

            try:
                ev['title'] = (await page.title()) or None
            except Exception:
                ev['title'] = None
            try:
                ev['html'] = await page.content()
            except Exception:
                ev['html'] = ''
            try:
                ev['scriptSrc'] = await page.eval_on_selector_all(
                    'script[src]', 'els => els.map(e => e.src)')
            except Exception:
                ev['scriptSrc'] = []
            try:
                ev['meta'] = await page.evaluate(_META_JS)
            except Exception:
                ev['meta'] = {}
            try:
                cks = await context.cookies()
                ev['cookies'] = {c['name']: c.get('value', '') for c in cks}
            except Exception:
                ev['cookies'] = {}
            if js_paths:
                try:
                    ev['js'] = await page.evaluate(_JS_PROBE, list(js_paths))
                except Exception:
                    ev['js'] = {}

            if screenshot_path:
                try:
                    await page.screenshot(path=screenshot_path, full_page=full_page)
                    ev['screenshot'] = screenshot_path
                except Exception:
                    pass

            ev['error'] = None
        except Exception as e:
            ev['error'] = str(e).splitlines()[0] if str(e) else 'navigation failed'
        finally:
            if page is not None:
                try:
                    await page.close()
                except Exception:
                    pass
            if context is not None:
                try:
                    await context.close()
                except Exception:
                    pass
        return ev

    async def browse_host(self, host: str, *, schemes=('https', 'http'),
                          **kwargs) -> Dict[str, Any]:
        """
        Browse a bare hostname, trying each scheme in turn (https then http) and
        returning the first that responds. ``kwargs`` are forwarded to browse().
        The returned dict carries an extra ``input`` key (the original host).
        """
        host = (host or '').strip().lower()
        last = None
        for scheme in schemes:
            ev = await self.browse(f"{scheme}://{host}", **kwargs)
            ev['input'] = host
            if ev.get('status') is not None and not ev.get('error'):
                return ev
            last = ev
        if last is None:
            last = {'input': host, 'url': None, 'final_url': None, 'status': None,
                    'title': None, 'server': None, 'headers': {}, 'html': '',
                    'scriptSrc': [], 'meta': {}, 'cookies': {}, 'js': {},
                    'screenshot': None, 'error': 'navigation failed',
                    'timestamp': time.time()}
        return last

    def close(self):
        """Close the session and clean up resources."""
        try:
            self.session.close()
        except Exception as e:
            if self.logger:
                self.logger.error(f"CLOSE ERROR: {e}")
            elif self.debug:
                print(f"\033[31m[CLOSE ERROR]\033[m {e}")
