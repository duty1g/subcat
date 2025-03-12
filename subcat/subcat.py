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
from typing import List, Optional, Set, Dict
from queue import Queue
import importlib.resources as pkg_resources

if __package__:
    from .logger import Logger
    from .navigator import Navigator
    from .detector import Detector
else:
    from logger import Logger
    from navigator import Navigator
    from detector import Detector

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
version = '1.3.1'


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
                 config: str = 'config.yaml'):
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
        self.found_domains = set()
        self.processed_domains = set()
        self.lock = Lock()
        self.exit_event = threading.Event()
        self.scope = self._load_scope(scope) if scope else None
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
        """Runs a subdomain enumeration module."""
        if self.exit_event.is_set():
            return []
        try:
            if __package__:
                module = importlib.import_module(f"subcat.modules.{module_name}")
            else:
                module = importlib.import_module(f"modules.{module_name}")
            results = module.returnDomains(self.domain, self.logger, self.config, self.reverse, self.scope)
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

    def _process_domain(self, domain: str) -> Optional[str]:
        """Processes a discovered subdomain."""
        if self.exit_event.is_set():
            return None
        with self.lock:
            if domain in self.processed_domains:
                return None
            self.processed_domains.add(domain)
        ip_address = None
        if self.ip or self.scope:
            try:
                ip_address = socket.gethostbyname(domain)
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

            # If the domain is dead, output a specific schema.
            # print(str(status).upper())
            result = ''
            if status is None:
                if not self.up:
                    result = f"{domain} {red}[DEAD]{reset}"
                    if self.ip and ip_address:
                        result += f" {blue}[{ip_address}]{reset}"
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
                except Exception as e:
                    self.logger.debug(f"Tech detection failed for {domain}: {e}")
        else:
            result = domain
        if self.ip and ip_address:
            result += f" {blue}[{ip_address}]{reset}"
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
        start_time = time.time()
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
                    if self.output:
                        try:
                            with open(self.output, 'a') as f:
                                f.write(res + '\n')
                        except Exception as e:
                            self.logger.error(f"Output write error: {e}")

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
            elapsed = end_time - start_time
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
                config=args.config
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
