from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
try:
    from subcat.navigator import Navigator
    from subcat.config import Config
except:
    from navigator import Navigator
    from config import Config

# Endpoints for SecurityTrails
URL_API_DOMAIN = 'https://api.securitytrails.com/v1/domain/{}/subdomains'
URL_API_REVERSE = 'https://api.securitytrails.com/v1/domains/list?include_ips=false&scroll=false'
REVERSE_LOOKUP_SUPPORTED = True


def returnDomains(domain: str, logger, conf: str, reverse: bool = False, scope_list: List[str] = None) -> List[str]:
    domains = set()
    keys = Config(config=conf, logger=logger).read('securitytrails') or []
    if not keys:
        logger.error("No API key found for SecurityTrails")
        return list(domains)

    if not reverse:
        # Normal mode: use the domain endpoint.
        api_url = URL_API_DOMAIN.format(domain)
        for key in keys:
            try:
                with Navigator(debug=logger.level >= 2, timeout=20, verify_ssl=False) as nav:
                    response = nav.request(
                        api_url,
                        response_type='json',
                        method='GET',
                        headers={'APIKEY': key}
                    )
                    debug_info = nav.get_debug_info()
                    logger.verbose(f"SecurityTrails Status Code: {debug_info.get('status_code')}")
                    logger.verbose(f"SecurityTrails Final URL: {debug_info.get('final_url')}")
                    logger.verbose(f"SecurityTrails Response Preview: {debug_info.get('partial_content')}")
                    status_code = debug_info.get('status_code')
                    if status_code == 429:
                        logger.error(f"SecurityTrails: API key {key[-4:]} rate limited; rotating key.")
                        continue
                    if response and 'subdomains' in response and response['subdomains']:
                        for sub in response['subdomains']:
                            # Build full subdomain by appending the base domain.
                            domains.add(f"{sub}.{domain}".lower())
                        logger.debug(f"SecurityTrails: Found {len(domains)} subdomains using key {key[-4:]}")
                        break
                    else:
                        logger.error(f"SecurityTrails: Invalid or empty response with key {key[-4:]}")
            except Exception as e:
                logger.error(f"SecurityTrails: Error ({key[-4:]}): {e}")
        return list(domains)
    else:
        # Reverse mode: require a scope_list of IP addresses.
        if not scope_list:
            logger.error("Reverse lookup mode requires a list of IPs (scope_list) to be provided.")
            return list(domains)

        def query_ip(ip: str, key: str) -> List[str]:
            local_domains = []
            # Prepare the JSON payload for the POST request.
            payload = json.dumps({"filter": {"ipv4": ip}})
            try:
                with Navigator(debug=logger.level >= 2, timeout=20, verify_ssl=False) as nav:
                    response = nav.request(
                        URL_API_REVERSE,
                        response_type='json',
                        method='POST',
                        headers={'APIKEY': key, 'content-type': 'application/json'},
                        data=payload
                    )
                    debug_info = nav.get_debug_info()
                    logger.verbose(f"SecurityTrails (IP {ip}) Status Code: {debug_info.get('status_code')}")
                    logger.verbose(f"SecurityTrails (IP {ip}) Final URL: {debug_info.get('final_url')}")
                    logger.verbose(f"SecurityTrails (IP {ip}) Response Preview: {debug_info.get('partial_content')}")
                    if debug_info.get('status_code') == 429:
                        logger.error(f"SecurityTrails (IP {ip}): API key {key[-4:]} rate limited; rotating key.")
                        return local_domains
                    if response and 'domains' in response and response['domains']:
                        for d in response['domains']:
                            # Only add domains that match the target domain.
                            if d.lower().endswith(domain.lower()):
                                local_domains.append(d.lower())
                        logger.debug(
                            f"SecurityTrails (IP {ip}): Found {len(local_domains)} domains using key {key[-4:]}")
                    else:
                        logger.error(f"SecurityTrails (IP {ip}): Invalid or empty response with key {key[-4:]}")
            except Exception as e:
                logger.error(f"SecurityTrails (IP {ip}): Error with key ending {key[-4:]}: {e}")
            return local_domains

        # Iterate over API keys and run queries concurrently for each IP in scope_list.
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
                logger.debug(f"SecurityTrails (reverse): Total found domains: {len(domains)} using key {key[-4:]}")
                break
        return list(domains)
