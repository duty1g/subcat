from typing import List
from urllib.parse import urlparse
try:
    from subcat.navigator import Navigator
except:
    from navigator import Navigator

URL_API = 'http://web.archive.org/cdx/search/cdx?url=*.{}/*&output=txt&fl=original&collapse=urlkey'


def is_valid_subdomain(subdomain: str, domain: str) -> bool:
    return subdomain and subdomain.endswith(domain) and subdomain != domain


def returnDomains(domain: str, logger, conf: str, reverse: bool = False, scope_list: List[str] = None) -> List[str]:
    domains = set()
    try:
        with Navigator(debug=logger.level >= 2, timeout=30, verify_ssl=False) as nav:
            api_url = URL_API.format(domain)
            response = nav.request(
                url=api_url,
                method='GET',
                response_type='text'
            )
            if not response:
                logger.error("Wayback: No response or request failed.")
                return []
            debug_info = nav.get_debug_info()
            logger.verbose(f"Wayback Status Code: {debug_info.get('status_code')}")
            logger.verbose(f"Wayback Final URL: {debug_info.get('final_url')}")
            logger.verbose(f"Wayback Response Size: {debug_info.get('response_size')} bytes")
            logger.verbose(f"Wayback Response Preview: {debug_info.get('partial_content', 'No content')[:500]}")
            new_domains = 0
            for line in response.strip().split('\n'):
                host = urlparse(line.strip()).hostname
                if host:
                    clean_host = host.lower().strip('*.')
                    if is_valid_subdomain(clean_host, domain) and clean_host not in domains:
                        domains.add(clean_host)
                        new_domains += 1
            logger.debug(f"Wayback: Found {new_domains} new subdomains")
    except Exception as e:
        logger.error(f"Wayback: Critical error: {e}")
    logger.debug(f"Wayback: Total unique subdomains: {len(domains)}")
    return sorted(domains)
