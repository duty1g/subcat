from typing import List
try:
    from subcat.navigator import Navigator
    from subcat.config import Config
except:
    from navigator import Navigator
    from config import Config

URL_API = 'https://api.dnsdumpster.com/domain/{}'


def returnDomains(domain: str, logger, conf: str, reverse: bool = False, scope_list: List[str] = None) -> List[str]:
    domains = set()
    keys = Config(config=conf, logger=logger).read('dnsdumpster') or []
    if not keys:
        logger.error("No API key found for DNSDumpster")
        return list(domains)

    for key in keys:
        try:
            with Navigator(debug=logger.level >= 2, timeout=20, verify_ssl=False) as nav:
                response = nav.request(
                    URL_API.format(domain),
                    response_type='json',
                    method='GET',
                    headers={'X-API-Key': key}
                )
                debug_info = nav.get_debug_info()
                logger.verbose(f"DNSDumpster Status Code: {debug_info.get('status_code')}")
                logger.verbose(f"DNSDumpster Final URL: {debug_info.get('final_url')}")
                logger.verbose(f"DNSDumpster Response Preview: {debug_info.get('partial_content')}")
                if not response:
                    logger.error("DNSDumpster: Empty response")
                    continue

                for rec_type in ['a', 'ns', 'cname', 'mx']:
                    if rec_type in response and isinstance(response[rec_type], list):
                        for rec in response[rec_type]:
                            host = rec.get('host', '')
                            if host and domain.lower() in host.lower():
                                domains.add(host.lower())
                logger.debug(f"DNSDumpster: Found {len(domains)} subdomains so far")
                if domains:
                    break
        except Exception as e:
            logger.error(f"DNSDumpster: Error with key ending {key[-4:]}: {e}")
    return list(domains)
