from typing import List
try:
    from subcat.navigator import Navigator
    from subcat.config import Config
except:
    from navigator import Navigator
    from config import Config

URL_API = "https://api.digitalyama.com/subdomain_finder?domain={}"


def returnDomains(domain: str, logger, conf: str, reverse: bool = False, scope_list: List[str] = None) -> List[str]:
    domains = set()
    keys = Config(config=conf, logger=logger).read('digitalyama') or []
    if not keys:
        logger.error("DigitalYama: No API keys found in configuration")
        return list(domains)

    for key in keys:
        try:
            with Navigator(debug=logger.level >= 2, timeout=20, verify_ssl=False) as nav:
                url = URL_API.format(domain)
                response = nav.request(
                    url,
                    response_type="json",
                    method="GET",
                    headers={"x-api-key": key}
                )
                debug_info = nav.get_debug_info()
                logger.verbose(f"DigitalYama Status Code: {debug_info.get('status_code')}")
                logger.verbose(f"DigitalYama Final URL: {debug_info.get('final_url')}")
                logger.verbose(f"DigitalYama Response Preview: {debug_info.get('partial_content')}")
                if not response:
                    logger.error("DigitalYama: Empty response")
                    continue
                if debug_info.get("status_code") != 200:
                    logger.error(f"DigitalYama: Received status code {debug_info.get('status_code')}")
                    continue
                if "subdomains" in response and response["subdomains"]:
                    for sub in response["subdomains"]:
                        domains.add(sub.lower())
                    logger.debug(f"DigitalYama: Found {len(response['subdomains'])} subdomains using key {key[-4:]}")
                    break
                else:
                    logger.error("DigitalYama: Invalid API response structure or no 'subdomains' key")
        except Exception as e:
            logger.error(f"DigitalYama: Error with key ending {key[-4:]}: {e}")
    return list(domains)
