# -*- coding: utf-8 -*-
import argparse
import importlib
import ipaddress
import os
import pathlib
import re
import signal
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from typing import List, Optional, Set, Dict, Any, Union
from queue import Queue
import importlib.resources as pkg_resources
import json

if __package__:
    from .logger import Logger
    from .navigator import Navigator
    from .detector import Detector
    from .cache import Cache
    from .output import OutputFormatter
else:
    from logger import Logger
    from navigator import Navigator
    from detector import Detector
    from cache import Cache
    from output import OutputFormatter

reset = '\033[m'
light_grey = '\033[37m'
dark_grey = '\033[90m'
red = '\033[31m'
green = '\033[32m'
bold = '\033[1m'
yellow = '\033[93m'
blue = '\033[96m'
bright_red = '\033[91m'
animation = "⢿⣻⣽⣾⣷⣯⣟⡿"

default_config = """binaryedge: []
virustotal: []
securitytrails: []
shodan: []
bevigil: []
chaos: []
dnsdumpster: []
netlas: []
digitalyama: []
censys: []
dnsarchive: []
"""
version = '1.4.0'


def banner():
    head = '''
\t                      {1};            ;
\t                    {0}ρ{1}ββΚ          ;ββΝ
\t                  {0}έΆχββββββββββββββββββΒ
\t                {0};ΣΆχΜ΅΅ΫΝββββββββ Ϋ΅ΫβββΝ
\t               {0}όΆΆχβ   {2}Ά{1}   ββββ΅  {2}Ά΅{1}  βββββ
\t              {0}χΆΆΆφβΒ; {2}Ϋ΅{1};έββββΒ; {2}Ϋ΅{1} ρββββββ
\t              {0}ΆΆΆΆδβββββββββ{0};χ{1}ββββββμβββββββ
\t              {0}ΪχχχχΧβββββββββββββββββββθθθθΚ
\t             {0}·ϊβθβζ  {1}Ϊθθβββββββββββββββμ ;όβΫ΅
\t              {0}·΅   ΅ΫΫΫΆΆθ{1}βββββββββθθΫ΅   ΅Ϋ΅
\t                      {0};ΣΆθββββΒΝρρρμ
\t                     {0};ΣΆΆβββββββββββμ{3}
\t ▄∞∞∞∞∞▄, ╒∞∞▄   ∞∞▄ ▄∞∞∞∞∞∞▄   ,▄∞∞∞∞▄      ▄∞∞4▄  ╒∞∞∞∞∞∞∞▄,
\t▐▄ ═▄▄▄ ▐█▐ ,▀  j' █▌█  ▄▄▄ ▀█▌█▀ ╓▄▄  ▀▄  ¡█  , ▐█ ▐▄▄▄  ▄▄██
\t▐▄ `'""▀██▐  █▌ j  █▌█  `"" ▄█▌█ ▐█▀`▀▄██' M  $██  █, `█ ▐█```
\tj▀▀███▌ ▐█▐  ▀▌▄█  ▀▀█ ▐███  █▌▄ ▀█▄▄▀ ▐█M▀.       ▀█▄.▀ J▀
\t╚▄,,¬¬⌐▄█▌ ▀▄,,, ▄██ █,,,,,▓██▌ ▀▄,,,,▄█╩j▌,██▀▀▀▀▌,█▌`█,▐█
\t  ▀▀▀▀▀▀▀    ▀▀▀▀▀▀ ""▀▀▀▀▀▀      ▀▀▀""`  ▀▀▀     ▀▀▀   ▀▀▀
\t               {0}΅qΆΆΆΆ{1}βββββββββββββββββββββΡ΅
\t                  {0}ΫθΆΆΆ{1}ββββββββββββββββΡ΅
\t                      {1}΅ΫΫΫ΅ΝNNΝΫΫΫΐ΅Ϋ
\t                     v{5}{{{2}{6}{5}#dev}}{0}@{3}duty1g{1}
'''
    head = head.format(light_grey, dark_grey, red, yellow, reset, green, version)
    print(bold + head + reset)


class SubCat:
    """Enumerates subdomains and checks domain status and technologies."""

    def __init__(self,
                 domain: str,
                 output: Optional[str],
                 threads: int = 50,
                 scope: Optional[str] = None,
                 logger: object = None,
                 status_code: bool = False,
                 title: bool = False,
                 ip: bool = False,
                 up: bool = False,
                 tech: bool = False,
                 reverse: bool = False,
                 match_codes: Optional[List[int]] = None,
                 sources: Optional[List[str]] = None,
                 exclude_sources: Optional[List[str]] = None,
                 config: str = 'config.yaml',
                 use_cache: bool = True,
                 cache_ttl: int = 86400,
                 output_format: str = 'txt'):
        self.domain = domain.lower().strip()
        self.threads = threads
        self.match_codes = match_codes or []
        self.sources = sources
        self.exclude_sources = exclude_sources
        self.logger = logger
        self.status_code = status_code
        self.title = title
        self.ip = ip
        self.up = up
        self.tech = tech
        self.reverse = reverse
        self.output = output
        self.output_format = output_format.lower()
        self.found_domains = set()
        self.processed_domains = set()
        self.processed_results = []  # Store processed results for output
        self.lock = Lock()
        self.exit_event = threading.Event()
        self.scope = self._load_scope(scope) if scope else None
        self.use_cache = use_cache
        self.cache_ttl = cache_ttl
        self.output_file_handle = None
        self.output_initialized = False

        # Validate output format
        if self.output_format not in OutputFormatter.FORMATS:
            if self.logger:
                self.logger.warn(f"Unsupported output format: {self.output_format}. Using 'txt' instead.")
            self.output_format = 'txt'

        # Add appropriate extension to output file if specified
        if self.output:
            # Check if the output file already has an extension
            _, ext = os.path.splitext(self.output)
            # If no extension or different from the specified format, add the correct extension
            if not ext or ext[1:].lower() != self.output_format:
                self.output = f"{self.output}.{self.output_format}"
                if self.logger:
                    self.logger.debug(f"Added extension to output file: {self.output}")

            # Initialize output file
            self._initialize_output_file()

        # Initialize cache if enabled
        if self.use_cache:
            self.cache = Cache(ttl=self.cache_ttl)
            # Clear expired cache entries
            cleared = self.cache.clear_expired()
            if cleared > 0 and self.logger:
                self.logger.debug(f"Cleared {cleared} expired cache entries")

        signal.signal(signal.SIGINT, self.signal_handler)

        if config is None:
            home = os.path.expanduser("~")
            default_config_path = os.path.join(home, ".subcat", "config.yaml")
            config_dir = os.path.dirname(default_config_path)
            os.makedirs(config_dir, exist_ok=True)
            if not os.path.exists(default_config_path):
                try:
                    with open(default_config_path, 'w') as f:
                        f.write(default_config)
                    self.logger.info(f"Default config created at: {dark_grey}{default_config_path}{reset}")
                except Exception as e:
                    self.logger.error(f"Failed to create default config: {e}")

            self.config = default_config_path
            self.logger.info(f"Using config: {dark_grey}{self.config}{reset}")
        else:
            self.config = config
            self.logger.info(f"Using config: {dark_grey}{self.config}{reset}")

    def signal_handler(self, signum, frame):
        """Handles shutdown signal."""
        self.exit_event.set()
        self.logger.info("Shutting down gracefully...")

        # Finalize output file if it's open
        if self.output and self.output_file_handle:
            try:
                self._finalize_output_file()
                self.logger.info(f"Output file finalized during shutdown: {self.output}")
            except Exception as e:
                self.logger.error(f"Error finalizing output file during shutdown: {e}")

        os._exit(1)

    def _load_scope(self, scope_input: str) -> Set[str]:
        """Loads the IP scope list from a file or a direct IP/CIDR string."""
        self.logger.debug("Loading scope list")
        scope_ips = set()

        # Check if the scope_input is a file
        if os.path.exists(scope_input):
            try:
                with open(scope_input, 'r') as f:
                    lines = f.readlines()
            except Exception as e:
                self.logger.warn(f"Error loading scope file: {e}")
                return scope_ips

            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    network = ipaddress.ip_network(line, strict=False)
                    # For a /32 or any network with only one address, add that address
                    if network.num_addresses == 1:
                        scope_ips.add(str(network.network_address))
                    else:
                        scope_ips.update(str(ip) for ip in network.hosts())
                except ValueError as e:
                    self.logger.warn(f"Invalid network range in file: {line} - {e}")
        else:
            # Treat scope_input as a direct IP or CIDR string
            try:
                network = ipaddress.ip_network(scope_input, strict=False)
                if network.num_addresses == 1:
                    scope_ips.add(str(network.network_address))
                else:
                    scope_ips.update(str(ip) for ip in network.hosts())
            except ValueError as e:
                self.logger.warn(f"Invalid scope input: {scope_input} - {e}")

        return scope_ips

    def _validate_subdomain(self, subdomain: str) -> bool:
        """Validates the subdomain belongs to the target domain."""
        return self.domain in subdomain.lower()

    def _module_worker(self, module_name: str) -> List[str]:
        """Runs a subdomain enumeration module with caching support."""
        if self.exit_event.is_set():
            return []

        # Create a cache key based on module name, domain, and reverse mode
        cache_key = f"{module_name}:{self.domain}:{self.reverse}"

        # Check cache first if enabled
        if self.use_cache:
            cached_results = self.cache.get(cache_key)
            if cached_results is not None:
                self.logger.debug(f"Using cached results for {module_name}")
                valid = [s.replace('*.', '') for s in cached_results if self._validate_subdomain(s)]
                with self.lock:
                    new_domains = [s for s in valid if s not in self.found_domains]
                    self.found_domains.update(new_domains)
                return new_domains

        try:
            if __package__:
                module = importlib.import_module(f"subcat.modules.{module_name}")
            else:
                module = importlib.import_module(f"modules.{module_name}")

            # Get results from the module
            results = module.returnDomains(self.domain, self.logger, self.config, self.reverse, self.scope)

            # Cache the results if enabled
            if self.use_cache and results:
                self.cache.set(cache_key, results)

            valid = [s.replace('*.', '') for s in results if self._validate_subdomain(s)]
            with self.lock:
                new_domains = [s for s in valid if s not in self.found_domains]
                self.found_domains.update(new_domains)
            return new_domains
        except Exception as e:
            self.logger.debug(f"Module {module_name} failed: {e}")
            return []

    def _load_modules(self) -> List[str]:
        """Loads available subdomain modules, optionally filtering for reverse lookup support."""
        modules = []
        if __package__:
            module_dir = pkg_resources.files("subcat.modules")
        else:
            module_dir = pathlib.Path(os.path.join(os.path.dirname(__file__), 'modules'))
        if not __package__ and not module_dir.exists():
            self.logger.warn(f"Modules directory missing: {module_dir}")
            return modules
        allowed = [s.lower() for s in self.sources] if self.sources else None
        exclude = [e.lower() for e in self.exclude_sources] if self.exclude_sources else None

        for entry in module_dir.iterdir():  # Changed from os.listdir(module_dir)
            fname = entry.name  # Get the filename from the entry
            if fname.endswith('.py') and fname != '__init__.py':
                module_name = fname[:-3]

                if allowed is not None and module_name.lower() not in allowed:
                    continue
                if exclude is not None and module_name.lower() in exclude:
                    continue
                try:
                    # When reverse lookup is needed, import the module to check its capabilities.
                    if self.reverse:
                        if __package__:
                            mod = importlib.import_module(f"subcat.modules.{module_name}")
                        else:
                            mod = importlib.import_module(f"modules.{module_name}")
                        # Option 1: Check a module-level flag
                        if not getattr(mod, "REVERSE_LOOKUP_SUPPORTED", False):
                            continue
                        # Option 2 (alternative): Inspect the signature for a "reverse" parameter
                        # import inspect
                        # sig = inspect.signature(mod.returnDomains)
                        # if 'reverse' not in sig.parameters:
                        #     continue
                        modules.append(module_name)
                    else:
                        # For normal mode, use the original check without importing.
                        if __package__:
                            spec = importlib.util.find_spec(f"subcat.modules.{module_name}")
                        else:
                            spec = importlib.util.find_spec(f"modules.{module_name}")
                        if spec and spec.loader and hasattr(spec.loader, 'load_module'):
                            modules.append(module_name)
                        else:
                            self.logger.error(f"Module {module_name} not found or cannot be loaded")
                except Exception as e:
                    self.logger.error(f"Invalid module {module_name}: {e}")
        return modules

    def get_domain_status(self, domain: str) -> Dict:
        """Determines the domain status, protocol, response, and title."""
        info = {"protocol": None, "status": None, "response": None, "title": ""}
        with Navigator() as nav:
            # Try HTTP GET first.
            try:
                resp = nav.request(f"http://{domain}", method="GET", response_type="full", allow_redirects=True)
                # info["protocol"] = "http"
                if str(resp.url).startswith("https://"):
                    info["protocol"] = "https"
                else:
                    info["protocol"] = "http"
                info["status"] = resp.status_code
                info["response"] = resp
            except Exception as e:
                if hasattr(e, 'response') and e.response is not None:
                    resp = e.response
                    info["protocol"] = "http"
                    info["status"] = resp.status_code
                    info["response"] = resp
            # If no valid HTTP response, try HTTPS GET.
            if info["status"] is None or str(info["status"]).upper() == "TIMEOUT":
                try:
                    resp = nav.request(f"https://{domain}", method="GET", response_type="full")
                    info["protocol"] = "https"
                    info["status"] = resp.status_code
                    info["response"] = resp
                except Exception as e:
                    if hasattr(e, 'response') and e.response is not None:
                        resp = e.response
                        info["protocol"] = "https"
                        info["status"] = resp.status_code
                        info["response"] = resp
                    else:
                        info["status"] = None
            if self.title and not info["status"] is None:
                try:
                    info["title"] = nav._extract_title(resp) or ""
                except Exception:
                    info["title"] = ""
        return info

    def _initialize_output_file(self):
        """Initialize the output file with appropriate headers based on format."""
        try:
            # Determine output format from file extension if not explicitly set
            output_format = self.output_format
            _, ext = os.path.splitext(self.output)
            if ext and ext[1:].lower() in OutputFormatter.FORMATS:
                output_format = ext[1:].lower()

            # Open the file for writing
            self.output_file_handle = open(self.output, 'w')

            # Write format-specific headers
            if output_format == 'json':
                # Start JSON array or object
                self.output_file_handle.write('{\n')
                self.output_file_handle.write('  "metadata": {\n')
                self.output_file_handle.write(f'    "domain": "{self.domain}",\n')
                self.output_file_handle.write(f'    "timestamp": {time.time()},\n')
                self.output_file_handle.write('    "settings": {\n')
                self.output_file_handle.write(f'      "status_code": {str(self.status_code).lower()},\n')
                self.output_file_handle.write(f'      "title": {str(self.title).lower()},\n')
                self.output_file_handle.write(f'      "ip": {str(self.ip).lower()},\n')
                self.output_file_handle.write(f'      "up": {str(self.up).lower()},\n')
                self.output_file_handle.write(f'      "tech": {str(self.tech).lower()},\n')
                self.output_file_handle.write(f'      "reverse": {str(self.reverse).lower()}\n')
                self.output_file_handle.write('    }\n')
                self.output_file_handle.write('  },\n')
                self.output_file_handle.write('  "domains": [\n')
            elif output_format == 'csv':
                # Write CSV header
                if self.status_code or self.title or self.ip or self.tech:
                    headers = ['domain']
                    if self.ip:
                        headers.append('ip')
                    if self.status_code:
                        headers.append('status')
                    if self.title:
                        headers.append('title')
                    if self.tech:
                        headers.append('technologies')
                    self.output_file_handle.write(','.join(headers) + '\n')
                else:
                    self.output_file_handle.write('domain\n')
            elif output_format == 'xml':
                # Write XML header
                self.output_file_handle.write('<?xml version="1.0" encoding="UTF-8"?>\n')
                self.output_file_handle.write('<subcat_results>\n')
                self.output_file_handle.write('  <metadata>\n')
                self.output_file_handle.write(f'    <domain>{self.domain}</domain>\n')
                self.output_file_handle.write(f'    <timestamp>{time.time()}</timestamp>\n')
                self.output_file_handle.write('    <settings>\n')
                self.output_file_handle.write(f'      <status_code>{str(self.status_code).lower()}</status_code>\n')
                self.output_file_handle.write(f'      <title>{str(self.title).lower()}</title>\n')
                self.output_file_handle.write(f'      <ip>{str(self.ip).lower()}</ip>\n')
                self.output_file_handle.write(f'      <up>{str(self.up).lower()}</up>\n')
                self.output_file_handle.write(f'      <tech>{str(self.tech).lower()}</tech>\n')
                self.output_file_handle.write(f'      <reverse>{str(self.reverse).lower()}</reverse>\n')
                self.output_file_handle.write('    </settings>\n')
                self.output_file_handle.write('  </metadata>\n')
                self.output_file_handle.write('  <domains>\n')

            self.output_initialized = True
            self.logger.debug(f"Output file initialized: {self.output} in {output_format} format")
        except Exception as e:
            self.logger.error(f"Failed to initialize output file: {e}")
            self.output_file_handle = None

    def _write_domain_to_output(self, domain: str, result_data: Dict[str, Any]):
        """Write a domain to the output file in real-time."""
        if not self.output_file_handle or not self.output_initialized:
            return

        try:
            # Determine output format from file extension if not explicitly set
            output_format = self.output_format
            _, ext = os.path.splitext(self.output)
            if ext and ext[1:].lower() in OutputFormatter.FORMATS:
                output_format = ext[1:].lower()

            # Write domain in the appropriate format
            if output_format == 'txt':
                self.output_file_handle.write(f"{domain}\n")
            elif output_format == 'json':
                # Write JSON object for this domain
                json_str = json.dumps(result_data, indent=4)
                # Remove the first and last brackets and add a comma if not the first entry
                json_str = json_str.strip()
                if len(self.processed_domains) > 1:
                    self.output_file_handle.write(',\n')
                self.output_file_handle.write('    ' + json_str)
            elif output_format == 'csv':
                # Write CSV row
                if self.status_code or self.title or self.ip or self.tech:
                    row = [domain]
                    if self.ip:
                        row.append(result_data.get('ip', ''))
                    if self.status_code:
                        row.append(str(result_data.get('status', '')))
                    if self.title:
                        row.append(result_data.get('title', ''))
                    if self.tech:
                        techs = result_data.get('technologies', [])
                        row.append(';'.join(techs) if techs else '')
                    self.output_file_handle.write(','.join([str(x).replace(',', '\\,') for x in row]) + '\n')
                else:
                    self.output_file_handle.write(f"{domain}\n")
            elif output_format == 'xml':
                # Write XML element for this domain
                self.output_file_handle.write(f'    <domain>\n')
                self.output_file_handle.write(f'      <name>{domain}</name>\n')
                if self.ip and result_data.get('ip'):
                    self.output_file_handle.write(f'      <ip>{result_data["ip"]}</ip>\n')
                if self.status_code and result_data.get('status') is not None:
                    self.output_file_handle.write(f'      <status>{result_data["status"]}</status>\n')
                if self.title and result_data.get('title'):
                    self.output_file_handle.write(f'      <title>{result_data["title"]}</title>\n')
                if self.tech and result_data.get('technologies'):
                    self.output_file_handle.write(f'      <technologies>\n')
                    for tech in result_data.get('technologies', []):
                        self.output_file_handle.write(f'        <technology>{tech}</technology>\n')
                    self.output_file_handle.write(f'      </technologies>\n')
                self.output_file_handle.write(f'    </domain>\n')

            # Flush to ensure real-time writing
            self.output_file_handle.flush()
        except Exception as e:
            self.logger.error(f"Failed to write domain to output file: {e}")

    def _finalize_output_file(self):
        """Finalize the output file with appropriate footers based on format."""
        if not self.output_file_handle or not self.output_initialized:
            return

        try:
            # Determine output format from file extension if not explicitly set
            output_format = self.output_format
            _, ext = os.path.splitext(self.output)
            if ext and ext[1:].lower() in OutputFormatter.FORMATS:
                output_format = ext[1:].lower()

            # Write format-specific footers
            if output_format == 'json':
                self.output_file_handle.write('\n  ],\n')
                self.output_file_handle.write(f'  "count": {len(self.processed_domains)},\n')
                self.output_file_handle.write(f'  "duration_seconds": {time.time() - self.start_time}\n')
                self.output_file_handle.write('}\n')
            elif output_format == 'xml':
                self.output_file_handle.write('  </domains>\n')
                self.output_file_handle.write(f'  <count>{len(self.processed_domains)}</count>\n')
                self.output_file_handle.write(f'  <duration_seconds>{time.time() - self.start_time}</duration_seconds>\n')
                self.output_file_handle.write('</subcat_results>\n')

            # Close the file
            self.output_file_handle.close()
            self.output_file_handle = None
            self.logger.info(f"Output file finalized: {self.output}")
        except Exception as e:
            self.logger.error(f"Failed to finalize output file: {e}")

    def _process_domain(self, domain: str) -> Optional[str]:
        """Processes a discovered subdomain."""
        if self.exit_event.is_set():
            return None
        with self.lock:
            if domain in self.processed_domains:
                return None
            self.processed_domains.add(domain)

        # Initialize result data structure for structured output
        result_data = {
            'domain': domain,
            'ip': None,
            'status': None,
            'protocol': None,
            'title': None,
            'technologies': None,
            'is_alive': False
        }

        ip_address = None
        if self.ip or self.scope:
            try:
                ip_address = socket.gethostbyname(domain)
                result_data['ip'] = ip_address
            except socket.gaierror:
                ip_address = None

        if self.scope:
            if ip_address is None or ip_address not in self.scope:
                return None

        if self.status_code or self.title or self.tech or self.up:
            info = self.get_domain_status(domain)
            protocol = info["protocol"] if info["protocol"] else "http"
            status = info["status"]
            req = info["response"]
            title_text = info["title"]

            result_data['protocol'] = protocol
            result_data['status'] = status
            result_data['title'] = title_text
            result_data['is_alive'] = status is not None

            # If the domain is dead, output a specific schema.
            result = ''
            if status is None:
                if not self.up:
                    result = f"{domain} {red}[DEAD]{reset}"
                    if self.ip and ip_address:
                        result += f" {blue}[{ip_address}]{reset}"

                    # Store the processed result data
                    with self.lock:
                        self.processed_results.append(result_data)
                        # Write to output file in real-time if specified
                        if self.output:
                            self._write_domain_to_output(domain, result_data)

                    return result

            # Otherwise, build the result as usual.
            result = f"{protocol}://{domain}"
            if self.status_code:
                def get_status_color(s):
                    try:
                        code = int(s)
                    except Exception:
                        return bright_red
                    if code in (200, 204):
                        return green
                    elif code in (301, 302, 307):
                        return blue
                    elif 400 <= code < 600:
                        return bright_red
                    else:
                        return yellow

                result += f" {get_status_color(status)}[{status}]{reset}"
            if self.title:
                result += f" {dark_grey}[{title_text[:30]}]{reset}"
            if self.tech:
                try:
                    detector = Detector(self.logger)
                    tech_list = detector.detect(domain, req)
                    if tech_list:
                        techs = ",".join(tech_list)
                        result += f" {yellow}[{techs}]{reset}"
                        result_data['technologies'] = tech_list
                except Exception as e:
                    self.logger.debug(f"Tech detection failed for {domain}: {e}")
        else:
            result = domain

        if self.ip and ip_address:
            result += f" {blue}[{ip_address}]{reset}"

        # Store the processed result data
        with self.lock:
            self.processed_results.append(result_data)
            # Write to output file in real-time if specified
            if self.output:
                self._write_domain_to_output(domain, result_data)

        return result

    def _animate_spinner(self, stop_event):
        """Animates a spinner during enumeration."""
        load = 0
        while not stop_event.is_set():
            spinner_char = animation[load % len(animation)]
            with self.lock:
                processed = len(self.processed_domains)
                total = len(self.found_domains)
                sys.stderr.write('\r\033[K')
                self.logger.stdout(f"Enumerating subdomains for {red}{self.domain}{reset}", spinner_char, processed,
                                   total)
                sys.stderr.flush()
                # time.sleep(0.05)
            load += 1

    def run(self):
        """Runs subdomain enumeration."""
        self.start_time = time.time()
        try:
            self.logger.info(f"Starting enumeration for {red}{self.domain}{reset}")
            modules = self._load_modules()
            self.logger.info(f"Loaded {yellow}{len(modules)}{reset} modules")
            result_queue = Queue()

            def result_callback(fut):
                try:
                    res = fut.result()
                    if res:
                        result_queue.put(res)
                except Exception as e:
                    self.logger.debug(f"Result callback error: {e}")

            def consumer():
                while True:
                    res = result_queue.get()
                    if res is None:
                        break
                    sys.stderr.write('\r\033[K')
                    sys.stderr.flush()
                    with self.lock:
                        sys.stderr.write('\r\033[K')
                        sys.stderr.flush()
                        self.logger.result(res)
                    # We'll handle output at the end of the run method

            consumer_thread = threading.Thread(target=consumer)
            consumer_thread.start()
            spinner_stop = threading.Event()
            spinner_thread = threading.Thread(target=self._animate_spinner, args=(spinner_stop,))
            spinner_thread.start()
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [executor.submit(self._module_worker, mod) for mod in modules]
                process_futures = []
                for future in as_completed(futures):
                    if self.exit_event.is_set():
                        break
                    new_domains = future.result()
                    for domain in new_domains:
                        pf = executor.submit(self._process_domain, domain)
                        pf.add_done_callback(result_callback)
                        process_futures.append(pf)
                for pf in as_completed(process_futures):
                    if self.exit_event.is_set():
                        break
                    _ = pf.result()
            spinner_stop.set()
            spinner_thread.join()
            result_queue.put(None)
            consumer_thread.join()
            end_time = time.time()
            elapsed = end_time - self.start_time
            minutes = int(elapsed // 60)
            seconds = int(elapsed % 60)
            milliseconds = int((elapsed % 1) * 1000)
            time_parts = []
            if minutes > 0:
                time_parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
            if seconds > 0 or (minutes == 0 and milliseconds > 0):
                time_parts.append(f"{seconds} second{'s' if seconds != 1 else ''}")
            if milliseconds > 0 or (minutes == 0 and seconds == 0):
                time_parts.append(f"{milliseconds} millisecond{'s' if milliseconds != 1 else ''}")
            time_str = " ".join(time_parts)
            self.logger.info(
                f"Completed with {len(self.processed_domains)} subdomains for {red}{self.domain}{reset} in {time_str}")

            # Finalize output file if specified
            if self.output:
                try:
                    # Finalize the output file
                    self._finalize_output_file()

                    # Determine output format from file extension if not explicitly set
                    output_format = self.output_format
                    _, ext = os.path.splitext(self.output)
                    if ext and ext[1:].lower() in OutputFormatter.FORMATS:
                        output_format = ext[1:].lower()

                    self.logger.info(f"Results written to {self.output} in {output_format} format")
                except Exception as e:
                    self.logger.error(f"Output finalization error: {e}")

            # Return the processed domains for programmatic use
            return list(self.processed_domains)
        except Exception as e:
            self.logger.error(f"Fatal error: {e}")
            sys.exit(1)


def is_valid_domain(domain: str) -> bool:
    """Validates whether the given string is a valid domain or subdomain."""
    pattern = re.compile(
        r'^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'
    )
    return bool(pattern.match(domain))


def argParserCommands():
    """Parses command-line arguments."""

    class CapitalisedHelpFormatter(argparse.HelpFormatter):
        def add_usage(self, usage, actions, groups, prefix=None):
            if prefix is None:
                banner()
                prefix = 'Usage: '
            return super(CapitalisedHelpFormatter, self).add_usage(usage, actions, groups, prefix)

    parser = argparse.ArgumentParser(add_help=False, formatter_class=CapitalisedHelpFormatter)
    input_grp = parser.add_argument_group('INPUT')
    input_grp.add_argument('-d', '--domain', help="Target domain to scan")
    input_grp.add_argument('-l', '--list', type=argparse.FileType('r'),
                           help="File containing list of domains",
                           default=sys.stdin if not sys.stdin.isatty() else None)
    input_grp.add_argument('--scope', nargs='?',
                           help="IP scope filter: provide either a file containing CIDR ranges or a single IP/CIDR string (e.g., '8.8.8.8' or '8.8.4.0/24'). This filter is required when reverse lookup is enabled."
                           )
    output_grp = parser.add_argument_group('OUTPUT')
    output_grp.add_argument("-o", "--output", help="Output file")
    output_grp.add_argument('-of', '--output-format', choices=OutputFormatter.FORMATS, default='txt',
                           help=f"Output format (default: txt, available: {', '.join(OutputFormatter.FORMATS)})")
    output_grp.add_argument('-title', '--title', action='store_true', help="Show page titles")
    output_grp.add_argument('-ip', '--ip', action='store_true', help="Resolve IP addresses")
    output_grp.add_argument('-sc', '--status-code', dest='status_code', action='store_true',
                            help="Show HTTP status codes")
    output_grp.add_argument('--up', action='store_true', help="Show only domains that are up (exclude TIMEOUT)")
    output_grp.add_argument('-td', '--tech', action='store_true', help="Show detected technologies")
    output_grp.add_argument('-nc', '--no-colors', action='store_true', help="Disable colored output in console")
    filters_grp = parser.add_argument_group('FILTERS')
    filters_grp.add_argument('-mc', '--match-codes',
                             type=lambda s: [int(x.strip()) for x in s.split(',') if x.strip().isdigit()],
                             help="Comma separated list of HTTP status codes to filter (e.g., 200,404)",
                             default=[])
    source_grp = parser.add_argument_group('SOURCE')
    source_grp.add_argument("-ls", dest='list_modules', action="store_true", help="List available modules and exit")
    source_grp.add_argument("-s", "--sources", type=lambda s: s.split(','),
                            help="Specific sources to use for discovery (comma-separated, e.g., crtsh,wayback)")
    source_grp.add_argument("-es", "--exclude-sources", type=lambda s: s.split(','),
                            help="Sources to exclude from enumeration (comma-separated, e.g., alienvault,crtsh)")
    source_grp.add_argument("-r", "--reverse", action="store_true",
                            help="Enable reverse lookup mode for enumeration (loads only modules supporting reverse lookup). Requires --scope to be provided.")
    config_grp = parser.add_argument_group('CONFIGURATION')
    config_grp.add_argument('-t', '--threads', type=int, default=50, help="Number of concurrent threads (default: 50)")
    config_grp.add_argument('-c', '--config', help="Path to YAML config file (default: config.yaml)")
    config_grp.add_argument('--no-cache', action='store_true', help="Disable caching of results")
    config_grp.add_argument('--cache-ttl', type=int, default=86400,
                           help="Time-to-live for cache entries in seconds (default: 86400 = 24 hours)")
    config_grp.add_argument('--clear-cache', action='store_true', help="Clear all cached data before running")
    debug_grp = parser.add_argument_group('DEBUG')
    debug_grp.add_argument('-v', '--verbose', action='count', default=0,
                           help="Increase verbosity level (-v, -vv, -vvv)")
    debug_grp.add_argument('-silent', '--silent', action='store_true', help="Suppress all output except results")
    debug_grp.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                           help="Show this help message and exit")
    return parser


def main():
    global bold, red, yellow, reset, green
    try:
        args = argParserCommands().parse_args()
        if args.no_colors:
            logger = Logger(level=args.verbose + 1, silent=args.silent, color=False)
            reset = ""
            light_grey = ""
            dark_grey = ""
            red = ""
            green = ""
            bold = ""
            yellow = ""
            blue = ""
            bright_red = ""
        else:
            logger = Logger(level=args.verbose + 1, silent=args.silent)
        # Handle cache clearing if requested
        if args.clear_cache:
            cache = Cache()
            if cache.clear():
                logger.info("Cache cleared successfully")
            else:
                logger.error("Failed to clear cache")

        if args.list_modules:
            banner()
            try:
                if __package__:
                    module_dir = pkg_resources.files("subcat.modules")
                else:
                    module_dir = pathlib.Path(os.path.join(os.path.dirname(__file__), 'modules'))
            except Exception as e:
                logger.error(f"Error accessing subcat.modules resources: {e}")
                sys.exit(1)
            # Use the Traversable API to iterate over the files.
            modules = [
                f.name[:-3] for f in module_dir.iterdir()
                if f.name.endswith('.py') and f.name != '__init__.py'
            ]
            logger.info(f"{bold}{red}{len(modules)} {yellow}Available modules: {reset}")
            for module in modules:
                logger.result(f"{green}{module}{reset}")
            sys.exit(0)
        if args.reverse and not args.scope:
            argParserCommands().print_help()
            print(
                f"\n{red}Error: Reverse lookup mode requires specifying a scope IP or a file containing CIDR ranges.{reset}")
            sys.exit(1)

        domains = []
        if args.domain:
            if is_valid_domain(args.domain):
                domains = [args.domain.strip()]
            else:
                argParserCommands().print_help()
                print(f"\n{red}Please enter valid domain! {reset}")
                sys.exit(0)

            if not args.silent and not len(sys.argv) == 1:
                banner()
        elif args.list:
            if not args.silent and not len(sys.argv) == 1:
                banner()
            domains = [line.strip() for line in args.list if line.strip()]
        else:
            argParserCommands().print_help()
            sys.exit(1)
        for domain in domains:
            if not domain:
                continue
            SubCat(
                domain=domain,
                output=args.output,
                threads=args.threads,
                scope=args.scope,
                logger=logger,
                status_code=args.status_code,
                title=args.title,
                ip=args.ip,
                up=args.up,
                tech=args.tech,
                reverse=args.reverse,
                match_codes=args.match_codes,
                sources=args.sources,
                exclude_sources=args.exclude_sources,
                config=args.config,
                use_cache=not args.no_cache,
                cache_ttl=args.cache_ttl,
                output_format=args.output_format
            ).run()
    except KeyboardInterrupt:
        logger = Logger()
        logger.warn("Operation cancelled by user")
    except Exception as e:
        logger = Logger()
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
