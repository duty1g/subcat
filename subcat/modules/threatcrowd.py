from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed
try:
    from subcat.navigator import Navigator
except:
    from navigator import Navigator

# Endpoints for ThreatCrowd
URL_API_DOMAIN = 'http://ci-www.threatcrowd.org/searchApi/v2/domain/report/?domain={}'
URL_API_IP = 'http://ci-www.threatcrowd.org/searchApi/v2/ip/report/?ip={}'
REVERSE_LOOKUP_SUPPORTED = True


def returnDomains(domain: str, logger, conf: str, reverse: bool = False, scope_list: List[str] = None) -> List[str]:
    domains = set()

    if not reverse:
        # Normal mode: use the domain-based GET endpoint.
        try:
            with Navigator(debug=logger.level >= 2, timeout=15, verify_ssl=False) as nav:
                response = nav.request(
                    URL_API_DOMAIN.format(domain),
                    response_type='json',
                    method='GET'
                )
                debug_info = nav.get_debug_info()
                logger.verbose(f"ThreatCrowd Domain Mode Status Code: {debug_info.get('status_code')}")
                logger.verbose(f"ThreatCrowd Domain Mode Final URL: {debug_info.get('final_url')}")
                logger.verbose(f"ThreatCrowd Domain Mode Response Preview: {debug_info.get('partial_content')}")
                if response and 'subdomains' in response:
                    valid_subs = [s.lower() for s in response['subdomains'] if domain.lower() in s.lower()]
                    domains.update(valid_subs)
                    logger.debug(f"ThreatCrowd: Found {len(valid_subs)} subdomains in domain mode")
                else:
                    logger.error("ThreatCrowd: Invalid API response structure or empty response in domain mode")
        except Exception as e:
            logger.error(f"ThreatCrowd: Error in domain mode: {e}")
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
                    response = nav.request(
                        URL_API_IP.format(ip),
                        response_type='json',
                        method='GET'
                    )
                    debug_info = nav.get_debug_info()
                    logger.verbose(f"ThreatCrowd Reverse Mode (IP {ip}) Status Code: {debug_info.get('status_code')}")
                    logger.verbose(f"ThreatCrowd Reverse Mode (IP {ip}) Final URL: {debug_info.get('final_url')}")
                    logger.verbose(
                        f"ThreatCrowd Reverse Mode (IP {ip}) Response Preview: {debug_info.get('partial_content')}")
                    # Expected response structure: a "resolutions" field that is a list of dicts.
                    if response and 'resolutions' in response and isinstance(response['resolutions'], list):
                        for rec in response['resolutions']:
                            resolved_domain = rec.get('domain', '').lower()
                            if resolved_domain and resolved_domain.endswith(domain.lower()):
                                local_domains.append(resolved_domain)
                        logger.debug(f"ThreatCrowd Reverse Mode (IP {ip}): Found {len(local_domains)} domains")
                    else:
                        logger.error(
                            f"ThreatCrowd Reverse Mode (IP {ip}): Invalid API response structure or empty response")
            except Exception as e:
                logger.error(f"ThreatCrowd Reverse Mode (IP {ip}): Error: {e}")
            return local_domains

        results = []
        with ThreadPoolExecutor(max_workers=len(scope_list)) as executor:
            future_to_ip = {executor.submit(query_ip, ip): ip for ip in scope_list}
            for future in as_completed(future_to_ip):
                res = future.result()
                if res:
                    results.extend(res)
        domains.update(results)
        logger.debug(f"ThreatCrowd Reverse Mode: Total found domains: {len(domains)}")
        return list(domains)
