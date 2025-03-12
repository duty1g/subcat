from typing import List
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from subcat.navigator import Navigator
except:
    from navigator import Navigator

URL_API_DOMAIN = 'https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns'
URL_API_IP = 'https://otx.alienvault.com/api/v1/indicators/IPv4/{}/passive_dns'
REVERSE_LOOKUP_SUPPORTED = True


def returnDomains(domain: str, logger, conf: str, reverse: bool = False, scope_list: List[str] = None) -> List[str]:
    domains = set()
    if not reverse:
        # Normal mode: use the domain endpoint.
        try:
            with Navigator(debug=logger.level >= 2, timeout=20, verify_ssl=False) as nav:
                response = nav.request(
                    URL_API_DOMAIN.format(domain),
                    response_type='json',
                    method='GET'
                )
                debug_info = nav.get_debug_info()
                logger.verbose(f"AlienVault Domain Mode Status Code: {debug_info.get('status_code')}")
                logger.verbose(f"AlienVault Domain Mode Final URL: {debug_info.get('final_url')}")
                logger.verbose(f"AlienVault Domain Mode Response Preview: {debug_info.get('partial_content')}")
                if not response:
                    logger.error("AlienVault: Empty response in domain mode")
                    return []
                if 'passive_dns' in response:
                    for entry in response['passive_dns']:
                        hostname = entry.get('hostname', '')
                        if hostname and domain.lower() in hostname.lower():
                            domains.add(hostname.lower())
                    logger.debug(f"AlienVault: Found {len(domains)} subdomains in domain mode")
                else:
                    logger.error("AlienVault: Invalid API response structure in domain mode")
                return list(domains)
        except Exception as e:
            logger.error(f"AlienVault: Critical error in domain mode: {e}")
            return []
    else:
        # Reverse mode: require a list of IP addresses.
        if not scope_list:
            logger.error("AlienVault reverse mode requires a list of IPs (scope_list) to be provided.")
            return list(domains)

        def query_ip(ip: str) -> List[str]:
            local_domains = []
            try:
                with Navigator(debug=logger.level >= 2, timeout=20, verify_ssl=False) as nav:
                    response = nav.request(
                        URL_API_IP.format(ip),
                        response_type='json',
                        method='GET'
                    )
                    debug_info = nav.get_debug_info()
                    logger.verbose(f"AlienVault Reverse Mode (IP {ip}) Status Code: {debug_info.get('status_code')}")
                    logger.verbose(f"AlienVault Reverse Mode (IP {ip}) Final URL: {debug_info.get('final_url')}")
                    logger.verbose(
                        f"AlienVault Reverse Mode (IP {ip}) Response Preview: {debug_info.get('partial_content')}")
                    if not response:
                        logger.error(f"AlienVault Reverse Mode (IP {ip}): Empty response")
                        return local_domains
                    if 'passive_dns' in response and isinstance(response['passive_dns'], list):
                        for entry in response['passive_dns']:
                            hostname = entry.get('hostname', '').lower()
                            if hostname and hostname.endswith(domain.lower()):
                                local_domains.append(hostname)
                        logger.debug(f"AlienVault Reverse Mode (IP {ip}): Found {len(local_domains)} subdomains")
                    else:
                        logger.error(f"AlienVault Reverse Mode (IP {ip}): Invalid API response structure")
            except Exception as e:
                logger.error(f"AlienVault Reverse Mode (IP {ip}): Critical error: {e}")
            return local_domains

        results = []
        with ThreadPoolExecutor(max_workers=len(scope_list)) as executor:
            future_to_ip = {executor.submit(query_ip, ip): ip for ip in scope_list}
            for future in as_completed(future_to_ip):
                res = future.result()
                if res:
                    results.extend(res)
        domains.update(results)
        logger.debug(f"AlienVault Reverse Mode: Total found subdomains: {len(domains)}")
        return list(domains)
