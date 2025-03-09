import re
import urllib.parse
import random
from typing import Optional, Union, Dict, Any
from urllib3.exceptions import InsecureRequestWarning
import requests
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
    """Advanced HTTP client with comprehensive debugging and security features"""

    DEFAULT_HEADERS = {
        'accept-language': 'en-GB,en;q=0.9',
        'cache-control': 'max-age=0',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'sec-ch-ua': '"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
    }

    VALID_METHODS = {'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'}

    def __init__(self,
                 debug: bool = False,
                 verify_ssl: bool = False,
                 timeout: float = 15.0,
                 user_agent: Optional[str] = None,
                 logger: Optional[Logger] = None):
        """
        :param logger: An instance of Logger to use for logging.
        """
        self.debug = debug
        self.session = requests.Session()
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.last_response = None
        self.last_raw_content = None
        self.last_url = None
        self.request_count = 0

        self.logger = logger

        # No custom retry strategies are set.
        headers = self.DEFAULT_HEADERS.copy()
        # Rotate user agent if none is provided.
        if user_agent is None:
            user_agent = random.choice(DEFAULT_USER_AGENTS)
        headers['user-agent'] = user_agent
        self.session.headers.update(headers)

        self.session.verify = verify_ssl
        if not verify_ssl:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    def request(self, url: str, method: str = 'GET', response_type: str = 'text', **kwargs: Any) -> Union[
        requests.Response, str, Dict[str, Any], None]:
        method = method.upper()
        self.request_count += 1

        if method not in self.VALID_METHODS:
            self._log_error(f"Invalid method: {method}")
            return None

        try:
            headers = kwargs.pop('headers', {})
            merged_headers = {**self.session.headers, **headers}
            allow_redirects = kwargs.pop('allow_redirects', True)
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
        if self.logger:
            self.logger.error(message)
        elif self.debug:
            print(f"\033[31m[HTTP ERROR]\033[m {message}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        try:
            self.session.close()
        except Exception as e:
            if self.logger:
                self.logger.error(f"CLOSE ERROR: {e}")
            elif self.debug:
                print(f"\033[31m[CLOSE ERROR]\033[m {e}")
