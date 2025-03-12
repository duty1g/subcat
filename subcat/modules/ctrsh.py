from typing import List
try:
    from subcat.navigator import Navigator
except:
    from navigator import Navigator

URL_API = 'https://crt.sh/?q={}&output=json'


def returnDomains(domain: str, logger, conf: str, reverse: bool = False, scope_list: List[str] = None) -> List[str]:
    domains = set()
    try:
        with Navigator(debug=logger.level >= 2, timeout=20, verify_ssl=False) as nav:
            response = nav.request(URL_API.format(domain), response_type='json', method='GET')
            debug_info = nav.get_debug_info()
            logger.verbose(f"CRT.sh Status Code: {debug_info.get('status_code')}")
            logger.verbose(f"CRT.sh Final URL: {debug_info.get('final_url')}")
            logger.verbose(f"CRT.sh Response Preview: {debug_info.get('partial_content')}")
            if response and isinstance(response, list):
                for entry in response:
                    try:
                        name = entry.get('common_name', '')
                        # print(entry)
                        if domain in name:
                            domains.add(name.lower())
                    except:
                        pass

                logger.debug(f"CRT.sh: Found {len(domains)} subdomains")
            else:
                logger.error("CRT.sh: Invalid API response structure or empty response")
    except Exception as e:
        logger.error(f"CRT.sh: Error: {e}")
    return list(domains)
