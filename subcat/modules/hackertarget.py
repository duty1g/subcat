from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed
try:
    from subcat.navigator import Navigator
except:
    from navigator import Navigator

URL_API_HOSTSEARCH = 'https://api.hackertarget.com/hostsearch/?q={}'
URL_API_REVERSEIP = 'https://api.hackertarget.com/reverseiplookup/?q={}'
REVERSE_LOOKUP_SUPPORTED = True


def returnDomains(domain: str, logger, conf: str, reverse: bool = False, scope_list: List[str] = None) -> List[str]:
    domains = set()
    if not reverse:
        try:
            with Navigator(debug=logger.level >= 2, timeout=15, verify_ssl=False) as nav:
                response = nav.request(URL_API_HOSTSEARCH.format(domain), response_type='text', method='GET')
                debug_info = nav.get_debug_info()
                logger.verbose(f"HackerTarget Hostsearch Status Code: {debug_info.get('status_code')}")
                logger.verbose(f"HackerTarget Hostsearch Final URL: {debug_info.get('final_url')}")
                logger.verbose(f"HackerTarget Hostsearch Response Preview: {debug_info.get('partial_content')}")
                if response:
                    for line in response.split('\n'):
                        parts = line.strip().split(',')
                        if parts and parts[0] and domain.lower() in parts[0].lower():
                            domains.add(parts[0].lower())
                    logger.debug(f"HackerTarget: Found {len(domains)} subdomains in hostsearch mode")
                else:
                    logger.error("HackerTarget: Empty response")
        except Exception as e:
            logger.error(f"HackerTarget: Error in hostsearch mode: {e}")
        return list(domains)
    else:
        # Reverse mode: require a list of IP addresses.
        if not scope_list:
            logger.error("Reverse lookup mode requires a list of IPs (scope_list) to be provided.")
            return list(domains)

        def query_ip(ip: str) -> List[str]:
            local_domains = []
            try:
                with Navigator(debug=logger.level >= 2, timeout=15, verify_ssl=False) as nav:
                    response = nav.request(URL_API_REVERSEIP.format(ip), response_type='text', method='GET')
                    debug_info = nav.get_debug_info()
                    logger.verbose(f"HackerTarget Reverse IP (IP {ip}) Status Code: {debug_info.get('status_code')}")
                    logger.verbose(f"HackerTarget Reverse IP (IP {ip}) Final URL: {debug_info.get('final_url')}")
                    logger.verbose(
                        f"HackerTarget Reverse IP (IP {ip}) Response Preview: {debug_info.get('partial_content')}")
                    if response:
                        for line in response.split('\n'):
                            domain_line = line.strip()
                            # Accept the domain if it ends with the target domain.
                            if domain_line and domain_line.lower().endswith(domain.lower()):
                                local_domains.append(domain_line.lower())
                        logger.debug(f"HackerTarget Reverse IP (IP {ip}): Found {len(local_domains)} subdomains")
                    else:
                        logger.error(f"HackerTarget Reverse IP (IP {ip}): Empty response")
            except Exception as e:
                logger.error(f"HackerTarget Reverse IP (IP {ip}): Error: {e}")
            return local_domains

        results = []
        with ThreadPoolExecutor(max_workers=len(scope_list)) as executor:
            future_to_ip = {executor.submit(query_ip, ip): ip for ip in scope_list}
            for future in as_completed(future_to_ip):
                res = future.result()
                if res:
                    results.extend(res)
        domains.update(results)
        logger.debug(f"HackerTarget Reverse IP: Total found subdomains: {len(domains)}")
        return list(domains)
