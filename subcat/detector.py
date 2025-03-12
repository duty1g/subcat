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
    def __init__(self, logger=None):
        self.logger = logger
        self.fingerprints = self.load_fingerprints()

    def load_fingerprints(self) -> dict:
        """
        Load fingerprints from the fingerprints.json file located in the same directory.
        """
        fingerprints_file = os.path.join(os.path.dirname(__file__), 'fingerprints.json')
        try:
            with open(fingerprints_file) as f:
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
        try:
            with Navigator(debug=self.logger is not None, logger=self.logger) as nav:
                return nav.request(url, method="GET", response_type="json")
        except Exception as e:
            if self.logger:
                self.logger.debug(f"Error loading AWS ranges: {e}")
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

    def detect(self, domain: str, response) -> list:
        """
        Detect technologies for the given domain using a single Navigator response.
        This version applies threading for faster detection.
        """
        detected = []
        page_content = response.text
        headers = response.headers
        headers_normalized = {k.lower(): v for k, v in headers.items()} if headers else {}

        # Get TLS info once.
        tls_info = ""
        try:
            cert = self.get_tls_certificate(domain)
            tls_info = self.extract_tls_info(cert)
        except Exception as e:
            if self.logger:
                self.logger.debug(f"TLS detection failed for {domain}: {e}")

        # Get CNAME records once.
        cname_records = self.get_cname(domain)

        # Define a function to check each technology.
        def check_tech(tech, rules):
            # Check header rules.
            if "headers" in rules:
                for header, patterns in rules["headers"].items():
                    header_value = headers_normalized.get(header.lower(), "")
                    if header_value:
                        if isinstance(patterns, list):
                            for pattern in patterns:
                                if re.search(pattern, header_value, re.IGNORECASE):
                                    return tech
                        elif isinstance(patterns, str):
                            if re.search(patterns, header_value, re.IGNORECASE):
                                return tech

            # Check HTML rules.
            if "html" in rules and page_content:
                patterns = rules["html"]
                if isinstance(patterns, list):
                    for pattern in patterns:
                        if re.search(pattern, page_content, re.IGNORECASE):
                            return tech
                elif isinstance(patterns, str):
                    if re.search(patterns, page_content, re.IGNORECASE):
                        return tech

            # Check meta rules.
            if "meta" in rules and page_content:
                patterns = rules["meta"]
                if isinstance(patterns, list):
                    for pattern in patterns:
                        if re.search(pattern, page_content, re.IGNORECASE):
                            return tech
                elif isinstance(patterns, str):
                    if re.search(patterns, page_content, re.IGNORECASE):
                        return tech

            # Check script rules.
            if "script" in rules and page_content:
                patterns = rules["script"]
                script_srcs = re.findall(r'<script[^>]+src=["\'](.*?)["\']', page_content, re.IGNORECASE)
                if isinstance(patterns, list):
                    for pattern in patterns:
                        for src in script_srcs:
                            if re.search(pattern, src, re.IGNORECASE):
                                return tech
                elif isinstance(patterns, str):
                    for src in script_srcs:
                        if re.search(patterns, src, re.IGNORECASE):
                            return tech

            # Check TLS rules.
            if tls_info and "tls" in rules:
                patterns = rules["tls"]
                if isinstance(patterns, list):
                    for pattern in patterns:
                        if re.search(pattern, tls_info, re.IGNORECASE):
                            return tech
                elif isinstance(patterns, str):
                    if re.search(patterns, tls_info, re.IGNORECASE):
                        return tech

            # Check CNAME rules.
            if "cname" in rules:
                patterns = rules["cname"]
                if not isinstance(patterns, list):
                    patterns = [patterns]
                for cname in cname_records:
                    for pattern in patterns:
                        if re.search(pattern, cname, re.IGNORECASE):
                            return tech

            # No match found.
            return None

        # Use ThreadPoolExecutor to run checks concurrently.
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_tech = {
                executor.submit(check_tech, tech, rules): tech
                for tech, rules in self.fingerprints.items()
            }
            for future in concurrent.futures.as_completed(future_to_tech):
                result = future.result()
                if result and result not in detected:
                    detected.append(result)

        # Process "implies" field.
        for tech in detected.copy():
            if tech in self.fingerprints:
                rule = self.fingerprints[tech]
                if "implies" in rule:
                    implied = rule["implies"]
                    if isinstance(implied, list):
                        for impl in implied:
                            if impl not in detected:
                                detected.append(impl)
                    elif isinstance(implied, str):
                        if implied not in detected:
                            detected.append(implied)

        # Extra AWS IP range check.
        def get_target_ip(target):
            try:
                return socket.gethostbyname(target)
            except Exception:
                return None

        target_ip = get_target_ip(domain)
        if target_ip:
            aws_ranges = self.load_aws_ranges()
            if aws_ranges and self.is_ip_in_aws(target_ip, aws_ranges):
                if "Amazon Web Services" not in detected:
                    detected.append("Amazon Web Services")
        return detected
