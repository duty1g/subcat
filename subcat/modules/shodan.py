from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed
try:
    from subcat.navigator import Navigator
    from subcat.config import Config
except:
    from navigator import Navigator
    from config import Config

URL_API_DOMAIN = 'https://api.shodan.io/dns/domain/{}?key={}'
URL_API_REVERSE = 'https://api.shodan.io/dns/reverse?ips={}&key={}'
REVERSE_LOOKUP_SUPPORTED = True


def returnDomains(domain: str, logger, conf: str, reverse: bool = False, scope_list: List[str] = None) -> List[str]:
    domains = set()
    keys = Config(config=conf, logger=logger).read('shodan') or []
    if not keys:
        logger.error("No API key found for Shodan")
        return list(domains)

    if not reverse:
        # Normal mode: use the domain-based endpoint.
        for key in keys:
            try:
                with Navigator(debug=logger.level >= 2, timeout=20, verify_ssl=False) as nav:
                    url = URL_API_DOMAIN.format(domain, key)
                    response = nav.request(
                        url,
                        response_type='json',
                        method='GET'
                    )
                    debug_info = nav.get_debug_info()
                    logger.verbose(f"Shodan Status Code: {debug_info.get('status_code')}")
                    logger.verbose(f"Shodan Final URL: {debug_info.get('final_url')}")
                    logger.verbose(f"Shodan Response Preview: {debug_info.get('partial_content')}")
                    if response and 'subdomains' in response and response['subdomains']:
                        valid_subs = [f"{s}.{domain}".lower() for s in response['subdomains']]
                        domains.update(valid_subs)
                        logger.debug(f"Shodan: Found {len(valid_subs)} subdomains using key {key[-4:]}")
                        break  # Stop after first key that returns valid data.
                    else:
                        logger.error("Shodan: Invalid API response structure or empty response")
            except Exception as e:
                logger.error(f"Shodan: Error ({key[-4:]}): {e}")
        return list(domains)
    else:
        # Reverse mode: require a list of IP addresses.
        if not scope_list:
            logger.error("Reverse lookup mode requires a list of IPs (scope_list) to be provided.")
            return list(domains)

        def query_ip(ip: str, key: str) -> List[str]:
            local_domains = []
            url = URL_API_REVERSE.format(ip, key)
            try:
                with Navigator(debug=logger.level >= 2, timeout=20, verify_ssl=False) as nav:
                    response = nav.request(
                        url,
                        response_type='json',
                        method='GET'
                    )
                    debug_info = nav.get_debug_info()
                    logger.verbose(f"Shodan Reverse (IP {ip}) Status Code: {debug_info.get('status_code')}")
                    logger.verbose(f"Shodan Reverse (IP {ip}) Final URL: {debug_info.get('final_url')}")
                    logger.verbose(f"Shodan Reverse (IP {ip}) Response Preview: {debug_info.get('partial_content')}")
                    # Expect response to be a dictionary where the key is the IP and the value is a list of hostnames.
                    if response and ip in response and isinstance(response[ip], list):
                        for host in response[ip]:
                            if host.lower().endswith(domain.lower()):
                                local_domains.append(host.lower())
                        logger.debug(
                            f"Shodan Reverse (IP {ip}): Found {len(local_domains)} subdomains using key {key[-4:]}")
                    else:
                        logger.error(f"Shodan Reverse (IP {ip}): Invalid or empty response with key {key[-4:]}")
            except Exception as e:
                logger.error(f"Shodan Reverse (IP {ip}): Error with key ending {key[-4:]}: {e}")
            return local_domains

        # Iterate over API keys and query each IP concurrently.
        for key in keys:
            results = []
            with ThreadPoolExecutor(max_workers=len(scope_list)) as executor:
                future_to_ip = {executor.submit(query_ip, ip, key): ip for ip in scope_list}
                for future in as_completed(future_to_ip):
                    res = future.result()
                    if res:
                        results.extend(res)
            if results:
                domains.update(results)
                logger.debug(f"Shodan Reverse: Total found subdomains: {len(domains)} using key {key[-4:]}")
                break
        return list(domains)
