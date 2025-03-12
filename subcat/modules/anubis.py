from typing import List
try:
    from subcat.navigator import Navigator
except:
    from navigator import Navigator

URL_API = 'https://jldc.me/anubis/subdomains/{}'


def returnDomains(domain: str, logger, conf: str, reverse: bool = False, scope_list: List[str] = None) -> List[str]:
    domains = set()
    try:
        with Navigator(debug=logger.level >= 2, timeout=20) as nav:
            response = nav.request(
                URL_API.format(domain),
                response_type='json',
                method='GET'
            )
            debug_info = nav.get_debug_info()
            logger.verbose(f"Anubis Status Code: {debug_info.get('status_code')}")
            logger.verbose(f"Anubis Final URL: {debug_info.get('final_url')}")
            logger.verbose(f"Anubis Response Preview: {debug_info.get('partial_content')}")
            if not response:
                logger.error("Anubis: Empty response")
                return []
            if isinstance(response, list):
                for subdomain in response:
                    if domain in subdomain:
                        domains.add(subdomain.lower())
                logger.debug(f"Anubis: Found {len(domains)} subdomains")
            else:
                logger.error("Anubis: Invalid API response structure")
            return list(domains)
    except Exception as e:
        logger.error(f"Anubis: Critical error: {e}")
        return []
