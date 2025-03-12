from typing import List
try:
    from subcat.navigator import Navigator
    from subcat.config import Config
except:
    from navigator import Navigator
    from config import Config

URL_API = 'https://dns.projectdiscovery.io/dns/{}/subdomains'


def returnDomains(domain: str, logger, conf: str, reverse: bool = False, scope_list: List[str] = None) -> List[str]:
    domains = set()
    keys = Config(config=conf, logger=logger).read('chaos') or []
    for key in keys:
        try:
            with Navigator(debug=logger.level >= 2, timeout=20, verify_ssl=False) as nav:
                response = nav.request(
                    URL_API.format(domain),
                    response_type='json',
                    method='GET',
                    headers={'Authorization': key}
                )
                debug_info = nav.get_debug_info()
                logger.verbose(f"Chaos Status Code: {debug_info.get('status_code')}")
                logger.verbose(f"Chaos Final URL: {debug_info.get('final_url')}")
                logger.verbose(f"Chaos Response Preview: {debug_info.get('partial_content')}")
                if not response:
                    logger.error("Chaos: Empty response")
                    continue
                if 'subdomains' in response and response['subdomains']:
                    for sub in response['subdomains']:
                        domains.add(f"{sub}.{domain}".lower())
                    logger.debug(f"Chaos: Found {len(domains)} subdomains using key {key[-4:]}")
                    break
                else:
                    logger.error("Chaos: Invalid API response structure")
        except Exception as e:
            logger.error(f"Chaos: Error ({key[-4:]}): {e}")
    return list(domains)
