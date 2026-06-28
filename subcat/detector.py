import re
import socket
import ipaddress
import os
import json
import concurrent.futures
if __package__:
    from .navigator import Navigator
else:
    from navigator import Navigator


class Detector:
    def __init__(self, logger=None, enable_tls_check=False):
        self.logger = logger
        self.fingerprints = self.load_fingerprints()
        self.enable_tls_check = enable_tls_check
        # Cache AWS ranges once instead of loading per domain (HUGE performance boost)
        self._aws_ranges_cache = None
        # Cached set of window.* paths referenced by `js` fingerprints, for the
        # Playwright probe (built lazily).
        self._js_paths = None

    def load_fingerprints(self) -> dict:
        """
        Load fingerprints from the fingerprints.json file located in the same directory.
        """
        fingerprints_file = os.path.join(os.path.dirname(__file__), 'fingerprints.json')
        try:
            # Must be utf-8: the file holds non-ASCII tech names and would fail
            # to decode under the platform default (e.g. cp1252 on Windows).
            with open(fingerprints_file, encoding='utf-8') as f:
                cached = json.load(f)
                return cached.get('apps', {})
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to load fingerprints: {e}")
            return {}

    def get_tls_certificate(self, hostname, port=443):
        import ssl
        context = ssl.create_default_context()
        conn = socket.create_connection((hostname, port))
        sock = context.wrap_socket(conn, server_hostname=hostname)
        cert = sock.getpeercert()
        sock.close()
        return cert

    def extract_tls_info(self, cert):
        details = ""
        subject = cert.get("subject", [])
        issuer = cert.get("issuer", [])
        for tup in subject:
            details += " ".join(val for key, val in tup) + " "
        for tup in issuer:
            details += " ".join(val for key, val in tup) + " "
        return details.strip()

    def get_cname(self, target):
        try:
            hostname, aliaslist, _ = socket.gethostbyname_ex(target)
            return aliaslist
        except Exception:
            return []

    def load_aws_ranges(self, url: str = "https://ip-ranges.amazonaws.com/ip-ranges.json") -> dict:
        """Load AWS IP ranges once and cache them (performance optimization)."""
        if self._aws_ranges_cache is not None:
            return self._aws_ranges_cache

        try:
            with Navigator(debug=self.logger is not None, logger=self.logger) as nav:
                self._aws_ranges_cache = nav.request(url, method="GET", response_type="json") or {}
                return self._aws_ranges_cache
        except Exception as e:
            if self.logger:
                self.logger.debug(f"Error loading AWS ranges: {e}")
            self._aws_ranges_cache = {}
            return {}

    def is_ip_in_aws(self, ip, aws_ranges) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            for prefix in aws_ranges.get("prefixes", []):
                network = ipaddress.ip_network(prefix["ip_prefix"])
                if ip_obj in network:
                    return True
        except Exception:
            pass
        return False

    # ---- Wappalyzer pattern helpers --------------------------------------

    @staticmethod
    def _regex_of(pattern: str) -> str:
        """
        Strip Wappalyzer tags (``\\;version:..``, ``\\;confidence:..``) from a
        pattern, leaving just the regex. An empty pattern means "exists".
        """
        if not pattern:
            return ''
        return pattern.split('\\;', 1)[0]

    @classmethod
    def _any_match(cls, patterns, values) -> bool:
        """True if any pattern matches any value (empty pattern = value exists)."""
        if values is None:
            return False
        if isinstance(values, str):
            values = [values]
        if not values:
            return False
        if isinstance(patterns, str):
            patterns = [patterns]
        for pat in (patterns or ['']):
            rx = cls._regex_of(pat)
            if rx == '':
                return True  # presence is enough
            for val in values:
                if val is None:
                    continue
                try:
                    if re.search(rx, str(val), re.IGNORECASE):
                        return True
                except re.error:
                    continue
        return False

    def js_probe_paths(self):
        """Unique ``window.*`` paths referenced by all `js` fingerprints."""
        if self._js_paths is None:
            paths = set()
            for rules in self.fingerprints.values():
                js = rules.get('js')
                if isinstance(js, dict):
                    paths.update(js.keys())
            self._js_paths = sorted(paths)
        return self._js_paths

    @staticmethod
    def _scripts_from_html(html: str):
        return re.findall(r'<script[^>]+src=["\'](.*?)["\']', html or '', re.IGNORECASE)

    @staticmethod
    def _meta_from_html(html: str):
        meta = {}
        for tag in re.findall(r'<meta\b[^>]*>', html or '', re.IGNORECASE):
            name = re.search(r'(?:name|property|http-equiv)\s*=\s*["\']([^"\']+)["\']', tag, re.IGNORECASE)
            content = re.search(r'content\s*=\s*["\']([^"\']*)["\']', tag, re.IGNORECASE)
            if name and content:
                meta.setdefault(name.group(1).lower(), []).append(content.group(1))
        return meta

    @staticmethod
    def _cookie_names(pattern: str, cookies: dict):
        """Cookie names in ``cookies`` matching a rule name (supports ``*``)."""
        if pattern in cookies:
            return [pattern]
        if '*' in pattern:
            rx = '^' + re.escape(pattern).replace(r'\*', '.*') + '$'
            return [n for n in cookies if re.match(rx, n, re.IGNORECASE)]
        return []

    # ---- detection entry points ------------------------------------------

    @staticmethod
    def _cookies_from_response(response) -> dict:
        """
        Cookie name->value from a requests.Response (and its redirect chain),
        falling back to parsing the Set-Cookie header. Enables the static path
        to match `cookies` fingerprints without a browser.
        """
        cookies = {}
        try:
            for resp in [response] + list(getattr(response, 'history', []) or []):
                jar = getattr(resp, 'cookies', None)
                if jar is not None:
                    for c in jar:
                        cookies.setdefault(c.name, c.value or '')
        except Exception:
            pass
        if not cookies:
            sc = (getattr(response, 'headers', {}) or {}).get('set-cookie')
            if sc:
                for part in re.split(r',(?=[^ ;]+=)', sc):
                    name = part.split('=', 1)[0].strip()
                    if name:
                        cookies.setdefault(name, '')
        return cookies

    def detect(self, domain: str, response) -> list:
        """
        Detect technologies from a single Navigator/requests response
        (static HTML + headers + cookies). No JS execution.
        """
        html = getattr(response, 'text', '') or ''
        headers = getattr(response, 'headers', {}) or {}
        evidence = {
            'html': html,
            'headers': {k.lower(): v for k, v in headers.items()},
            'scriptSrc': self._scripts_from_html(html),
            'meta': self._meta_from_html(html),
            'cookies': self._cookies_from_response(response),
            'js': {},
        }
        return self._match_fingerprints(domain, evidence)

    def detect_rich(self, domain: str, evidence: dict) -> list:
        """
        Detect technologies from live-page evidence collected by Playwright:
        rendered html, response headers, cookies, real script URLs, meta tags
        and ``window.*`` JS globals. Catches js/scriptSrc/cookies fingerprints a
        static fetch can't.
        """
        evidence = evidence or {}
        meta = evidence.get('meta') or {}
        ev = {
            'html': evidence.get('html') or '',
            'headers': {k.lower(): v for k, v in (evidence.get('headers') or {}).items()},
            'scriptSrc': evidence.get('scriptSrc') or [],
            'meta': {k.lower(): (v if isinstance(v, list) else [v]) for k, v in meta.items()},
            'cookies': evidence.get('cookies') or {},
            'js': evidence.get('js') or {},
        }
        return self._match_fingerprints(domain, ev)

    def _match_fingerprints(self, domain: str, ev: dict) -> list:
        """Match all fingerprints against the collected evidence (threaded)."""
        detected = []
        if not self.fingerprints:
            return detected

        html = ev.get('html', '')
        headers = ev.get('headers', {})
        cookies = ev.get('cookies', {})
        scriptsrc = ev.get('scriptSrc', [])
        metas = ev.get('meta', {})
        jsev = ev.get('js', {})

        tls_info = ""
        if self.enable_tls_check:
            try:
                tls_info = self.extract_tls_info(self.get_tls_certificate(domain))
            except Exception as e:
                if self.logger:
                    self.logger.debug(f"TLS detection failed for {domain}: {e}")
        cname_records = self.get_cname(domain)

        def check_tech(tech, rules):
            # headers
            hr = rules.get('headers')
            if hr:
                for h, pats in hr.items():
                    hv = headers.get(h.lower())
                    if hv is not None and self._any_match(pats, [hv]):
                        return tech
            # cookies
            cr = rules.get('cookies')
            if cr and cookies:
                for cname, pats in cr.items():
                    for n in self._cookie_names(cname, cookies):
                        if self._any_match(pats, [cookies[n] or '']):
                            return tech
            # js (window.* globals from the live page)
            jr = rules.get('js')
            if jr and jsev:
                for path, pats in jr.items():
                    if path in jsev and self._any_match(pats, [jsev[path] or '']):
                        return tech
            # scriptSrc (real loaded script URLs)
            sr = rules.get('scriptSrc')
            if sr and scriptsrc and self._any_match(sr, scriptsrc):
                return tech
            # html
            hh = rules.get('html')
            if hh and html and self._any_match(hh, [html]):
                return tech
            # meta
            mr = rules.get('meta')
            if mr:
                for mname, pats in mr.items():
                    contents = metas.get(mname.lower())
                    if contents and self._any_match(pats if pats else '', contents):
                        return tech
            # tls / cname (legacy keys, kept for compatibility)
            if tls_info and rules.get('tls') and self._any_match(rules['tls'], [tls_info]):
                return tech
            if rules.get('cname') and cname_records and self._any_match(rules['cname'], cname_records):
                return tech
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(50, len(self.fingerprints))) as executor:
            futures = {executor.submit(check_tech, tech, rules): tech
                       for tech, rules in self.fingerprints.items()}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result and result not in detected:
                    detected.append(result)

        # implies
        for tech in detected.copy():
            implied = self.fingerprints.get(tech, {}).get('implies')
            if isinstance(implied, str):
                implied = [implied]
            for impl in (implied or []):
                impl = impl.split('\\;', 1)[0]  # implies can carry confidence tags
                if impl and impl not in detected:
                    detected.append(impl)

        # AWS IP-range check
        try:
            target_ip = socket.gethostbyname(domain)
        except Exception:
            target_ip = None
        if target_ip:
            aws_ranges = self.load_aws_ranges()
            if aws_ranges and self.is_ip_in_aws(target_ip, aws_ranges):
                if "Amazon Web Services" not in detected:
                    detected.append("Amazon Web Services")
        return detected
