from typing import List
import re
try:
    from subcat.navigator import Navigator
    from subcat.config import Config
except:
    from navigator import Navigator
    from config import Config

URL_API = "https://dnsarchive.net/search?apikey={0}&q={1}"


def returnDomains(domain: str, logger, conf: str, reverse: bool = False, scope_list: List[str] = None) -> List[str]:
    domains = set()
    keys = Config(config=conf, logger=logger).read('dnsarchive') or []
    if not keys:
        logger.error("No API key found for DNSArchive; using free version.")
        keys = [""]

    for key in keys:
        try:
            with Navigator(debug=logger.level >= 2, timeout=20, verify_ssl=False) as nav:
                search_url = URL_API.format(key, domain)
                response = nav.request(search_url, response_type='text', method='GET')
                debug_info = nav.get_debug_info()
                logger.verbose(f"DNSArchive Status Code: {debug_info.get('status_code')}")
                logger.verbose(f"DNSArchive Final URL: {debug_info.get('final_url')}")
                logger.verbose(f"DNSArchive Response Preview: {debug_info.get('partial_content')[:500]}")
                if not response:
                    logger.error("DNSArchive: Empty response")
                    continue
                # Use regex to extract subdomains ending with the target domain.
                pattern = re.compile(r'([\w\.-]+\.' + re.escape(domain) + r')', re.IGNORECASE)
                matches = pattern.findall(response)
                if matches:
                    for match in matches:
                        domains.add(match.lower())
                    logger.debug(f"DNSArchive: Found {len(matches)} subdomains using key {key[-4:]}")
                    break  # Use only the first key that returns valid data.
                else:
                    logger.error("DNSArchive: Invalid API response structure or no subdomains found")
        except Exception as e:
            logger.error(f"DNSArchive: Error with key ending {key[-4:]}: {e}")
    return list(domains)
