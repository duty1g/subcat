from typing import List
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
try:
    from subcat.navigator import Navigator
except:
    from navigator import Navigator

URL_API_DOMAIN = 'https://urlscan.io/api/v1/search/?q=domain:{}'
URL_API_IP = 'https://urlscan.io/api/v1/search/?q=ip:{}'
REVERSE_LOOKUP_SUPPORTED = True


def returnDomains(domain: str, logger, conf: str, reverse: bool = False, scope_list: List[str] = None) -> List[str]:
    domains = set()
    if not reverse:
        try:
            with Navigator(debug=logger.level >= 2, timeout=20, verify_ssl=False) as nav:
                response = nav.request(URL_API_DOMAIN.format(domain), response_type='json', method='GET')
                debug_info = nav.get_debug_info()
                logger.verbose(f"Urlscan Status Code: {debug_info.get('status_code')}")
                logger.verbose(f"Urlscan Final URL: {debug_info.get('final_url')}")
                logger.verbose(f"Urlscan Response Preview: {debug_info.get('partial_content')}")
                if response and 'results' in response:
                    for result in response['results']:
                        url = result.get('page', {}).get('url', '')
                        host = urlparse(url).hostname
                        if host and domain.lower() in host.lower():
                            domains.add(host.lower())
                    logger.debug(f"Urlscan: Found {len(domains)} subdomains")
                else:
                    logger.error("Urlscan: Invalid API response structure or empty response")
        except Exception as e:
            logger.error(f"Urlscan: Error: {e}")
        return list(domains)
    else:
        # Reverse mode: require a list of IPs.
        if not scope_list:
            logger.error("Reverse lookup mode requires a list of IPs (scope_list) to be provided.")
            return list(domains)

        def query_ip(ip: str) -> List[str]:
            local_domains = []
            try:
                with Navigator(debug=logger.level >= 2, timeout=20, verify_ssl=False) as nav:
                    response = nav.request(URL_API_IP.format(ip), response_type='json', method='GET')
                    debug_info = nav.get_debug_info()
                    logger.verbose(f"Urlscan Reverse (IP {ip}) Status Code: {debug_info.get('status_code')}")
                    logger.verbose(f"Urlscan Reverse (IP {ip}) Final URL: {debug_info.get('final_url')}")
                    logger.verbose(f"Urlscan Reverse (IP {ip}) Response Preview: {debug_info.get('partial_content')}")
                    if response and 'results' in response:
                        for result in response['results']:
                            url = result.get('page', {}).get('url', '')
                            host = urlparse(url).hostname
                            if host and domain.lower() in host.lower():
                                local_domains.append(host.lower())
                        logger.debug(f"Urlscan Reverse (IP {ip}): Found {len(local_domains)} subdomains")
                    else:
                        logger.error(f"Urlscan Reverse (IP {ip}): Invalid API response structure or empty response")
            except Exception as e:
                logger.error(f"Urlscan Reverse (IP {ip}): Error: {e}")
            return local_domains

        results = []
        with ThreadPoolExecutor(max_workers=len(scope_list)) as executor:
            future_to_ip = {executor.submit(query_ip, ip): ip for ip in scope_list}
            for future in as_completed(future_to_ip):
                res = future.result()
                if res:
                    results.extend(res)
        domains.update(results)
        logger.debug(f"Urlscan Reverse: Total found subdomains: {len(domains)}")
        return list(domains)
