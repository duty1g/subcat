"""
Passive Subdomain Enumeration Module
Loads and runs OSINT modules to discover subdomains passive-ly.
"""
import importlib
import importlib.util
import importlib.resources as pkg_resources
import os
import pathlib
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Optional

if __package__:
    from .cache import Cache
else:
    from cache import Cache

class Passive:
    """Enumerates subdomains using passive OSINT modules."""

    def __init__(self,
                 domain: str,
                 sources: Optional[List[str]] = None,
                 exclude_sources: Optional[List[str]] = None,
                 reverse: bool = False,
                 scope: Optional[Set[str]] = None,
                 config: Optional[str] = None,
                 use_cache: bool = True,
                 cache_ttl: int = 86400,
                 threads: int = 50,
                 logger=None):
        self.domain = domain.lower().strip()
        self.sources = sources
        self.exclude_sources = exclude_sources
        self.reverse = reverse
        self.scope = scope
        self.config = config
        self.use_cache = use_cache
        self.cache_ttl = cache_ttl
        self.threads = threads
        self.logger = logger
        
        self.found_domains = set()
        self.domain_module_pairs = set()
        self.lock = threading.Lock()
        self.exit_event = threading.Event()
        
        if self.use_cache:
            self.cache = Cache(ttl=self.cache_ttl)
            if self.logger:
                cleared = self.cache.clear_expired()
                if cleared > 0:
                    self.logger.debug(f"Cleared {cleared} expired cache entries")

    @staticmethod
    def normalize_domain(domain: str) -> Optional[str]:
        if not domain:
            return None
        domain = domain.lower().strip()
        domain = domain.replace('*.', '').replace('*', '').strip('.')
        domain = ''.join(domain.split())
        normalized = ''
        for char in domain:
            if char.isalnum() or char in '.-':
                normalized += char
        domain = normalized
        while '..' in domain:
            domain = domain.replace('..', '.')
        domain = domain.strip('.')
        labels = domain.split('.')
        cleaned_labels = [label.strip('-') for label in labels if label.strip('-')]
        domain = '.'.join(cleaned_labels)
        if not domain or len(domain) > 253 or '.' not in domain:
            return None
        return domain

    def _validate_subdomain(self, subdomain: str) -> bool:
        return self.domain in subdomain.lower()

    def _load_modules(self) -> List[str]:
        modules = []
        if __package__:
            module_dir = pkg_resources.files("subcat.modules")
        else:
            module_dir = pathlib.Path(os.path.join(os.path.dirname(__file__), 'modules'))
        
        if not __package__ and not module_dir.exists():
            if self.logger:
                self.logger.warn(f"Modules directory missing: {module_dir}")
            return modules
            
        allowed = [s.lower() for s in self.sources] if self.sources else None
        exclude = [e.lower() for e in self.exclude_sources] if self.exclude_sources else None

        for entry in module_dir.iterdir():
            fname = entry.name
            if fname.endswith('.py') and fname != '__init__.py':
                module_name = fname[:-3]
                if allowed is not None and module_name.lower() not in allowed:
                    continue
                if exclude is not None and module_name.lower() in exclude:
                    continue
                try:
                    if __package__:
                        mod = importlib.import_module(f".modules.{module_name}", package=__package__)
                    else:
                        spec = importlib.util.spec_from_file_location(module_name, str(entry))
                        mod = importlib.util.module_from_spec(spec)
                        if spec.loader:
                            spec.loader.exec_module(mod)
                    if self.reverse and not getattr(mod, 'REVERSE_LOOKUP_SUPPORTED', False):
                        if self.logger:
                            self.logger.debug(f"Module {module_name} does not support reverse lookup")
                        continue
                    modules.append(module_name)
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Invalid module {module_name}: {e}")
        return modules

    def _module_worker(self, module_name: str) -> List[str]:
        if self.exit_event.is_set():
            return []
        
        cache_key = f"{module_name}:{self.domain}:{self.reverse}"
        
        if self.use_cache:
            cached_results = self.cache.get(cache_key)
            if cached_results is not None:
                if self.logger:
                    self.logger.debug(f"✓ Cache hit for {module_name} ({len(cached_results)} cached)")
                valid = []
                for s in cached_results:
                    normalized = self.normalize_domain(s)
                    if normalized and self._validate_subdomain(normalized):
                        valid.append(normalized)
                
                with self.lock:
                    new_domains = []
                    for domain in valid:
                        pair = (domain, module_name)
                        if pair not in self.domain_module_pairs:
                            self.domain_module_pairs.add(pair)
                            if domain not in self.found_domains:
                                self.found_domains.add(domain)
                                new_domains.append(domain)
                return new_domains

        try:
            if __package__:
                mod = importlib.import_module(f".modules.{module_name}", package=__package__)
            else:
                module_dir = pathlib.Path(__file__).parent / 'modules'
                spec = importlib.util.spec_from_file_location(module_name, str(module_dir / f"{module_name}.py"))
                mod = importlib.util.module_from_spec(spec)
                if spec.loader:
                    spec.loader.exec_module(mod)

            results = mod.returnDomains(self.domain, self.logger, self.config, self.reverse, self.scope)
            
            if self.use_cache and results:
                self.cache.set(cache_key, results)
                
            valid = []
            for s in results:
                normalized = self.normalize_domain(s)
                if normalized and self._validate_subdomain(normalized):
                    valid.append(normalized)
                    
            with self.lock:
                new_domains = []
                for domain in valid:
                    pair = (domain, module_name)
                    if pair not in self.domain_module_pairs:
                        self.domain_module_pairs.add(pair)
                        if domain not in self.found_domains:
                            self.found_domains.add(domain)
                            new_domains.append(domain)
                return new_domains
        except Exception as e:
            if self.logger:
                self.logger.debug(f"Module {module_name} failed: {e}")
            return []

    def run(self, module_started_callback=None, module_completed_callback=None, result_callback=None) -> List[str]:
        """
        Runs passive enumeration.
        
        :param module_started_callback: Optional callback func(module_name)
        :param module_completed_callback: Optional callback func(module_name, count)
        :param result_callback: Optional callback func(subdomain, module_name) called when subdomain found
        :return: List of modules
        """
        modules = self._load_modules()
        if self.logger:
            # debug-level: the CLI already prints a user-facing "Loaded N modules"
            # line, so keep this lower-level call from duplicating it.
            self.logger.debug(f"Loaded {len(modules)} modules")

        executor = ThreadPoolExecutor(max_workers=self.threads)
        module_futures = {}
        try:
            for mod in modules:
                future = executor.submit(self._module_worker, mod)
                module_futures[future] = mod
                if module_started_callback:
                    module_started_callback(mod)

            for future in as_completed(module_futures):
                if self.exit_event.is_set():
                    break
                module_name = module_futures[future]
                
                try:
                    new_domains = future.result()
                    
                    if result_callback:
                        for domain in new_domains:
                            result_callback(domain, module_name)
                            
                    if module_completed_callback:
                        module_completed_callback(module_name, len(new_domains))
                except Exception as e:
                    if self.logger:
                        self.logger.debug(f"Error processing module {module_name}: {e}")
        except KeyboardInterrupt:
            self.exit_event.set()
            for future in module_futures:
                future.cancel()
            raise
        finally:
            executor.shutdown(wait=False)
                    
        return modules

    def stop(self):
        self.exit_event.set()
