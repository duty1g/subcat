from typing import List
try:
    from subcat.navigator import Navigator
    from subcat.config import Config
except:
    from navigator import Navigator
    from config import Config

URL_API = 'https://osint.bevigil.com/api/{}/subdomains/'


def returnDomains(domain: str, logger, conf: str, reverse: bool = False, scope_list: List[str] = None) -> List[str]:
    domains = set()
    keys = Config(config=conf, logger=logger).read('bevigil') or []
    for key in keys:
        try:
            with Navigator(debug=logger.level >= 2, timeout=20, verify_ssl=False) as nav:
                response = nav.request(
                    URL_API.format(domain),
                    headers={'X-Access-Token': key},
                    response_type='json',
                    method='GET'
                )
                debug_info = nav.get_debug_info()
                logger.verbose(f"Bevigil Status Code: {debug_info.get('status_code')}")
                logger.verbose(f"Bevigil Final URL: {debug_info.get('final_url')}")
                logger.verbose(f"Bevigil Response Preview: {debug_info.get('partial_content')}")
                if not response:
                    logger.error("Bevigil: Empty response")
                    continue
                if 'subdomains' in response and response['subdomains']:
                    for sub in response['subdomains']:
                        domains.add(sub.lower())
                    logger.debug(f"Bevigil: Found {len(response['subdomains'])} subdomains using key {key[-4:]}")
                    break  # Use only the first key that returns data
                else:
                    logger.error("Bevigil: Invalid API response structure")
        except Exception as e:
            logger.error(f"Bevigil: Error ({key[-4:]}): {e}")
    return list(domains)
