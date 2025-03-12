from typing import List
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
try:
    from subcat.navigator import Navigator
    from subcat.config import Config
except:
    from navigator import Navigator
    from config import Config

URL_API = 'https://search.censys.io/api/v2/hosts/search'
REVERSE_LOOKUP_SUPPORTED = True


def returnDomains(domain: str, logger, conf: str, reverse: bool = False, scope_list: List[str] = None) -> List[str]:
    domains = set()
    keys = Config(config=conf, logger=logger).read('censys') or []
    if not keys:
        logger.error("No API key found for Censys")
        return list(domains)

    if not reverse:
        # Normal mode: query by domain.
        for key in keys:
            try:
                api_id, api_secret = key.split(':')
                auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
                with Navigator(debug=logger.level >= 2, timeout=30) as nav:
                    response = nav.request(
                        URL_API,
                        params={'q': f'names:{domain}', 'per_page': 1000},
                        headers={'Authorization': f'Basic {auth}'},
                        response_type='json',
                        method='GET'
                    )
                    debug_info = nav.get_debug_info()
                    logger.verbose(f"Censys Domain Mode Status Code: {debug_info.get('status_code')}")
                    logger.verbose(f"Censys Domain Mode Final URL: {debug_info.get('final_url')}")
                    logger.verbose(f"Censys Domain Mode Response Preview: {debug_info.get('partial_content')}")
                    if not response:
                        logger.error("Censys: Empty response in domain mode")
                        continue
                    if 'result' in response:
                        hits = response['result'].get('hits', [])
                        if hits:
                            for hit in hits:
                                for name in hit.get('names', []):
                                    if name.lower() and domain.lower() in name.lower():
                                        domains.add(name.lower())
                            logger.debug(f"Censys: Found {len(domains)} subdomains in domain mode using key {key[-4:]}")
                            break  # Use first key that returns valid data.
                        else:
                            logger.error("Censys: No hits found in domain mode")
                    else:
                        logger.error("Censys: Invalid API response structure in domain mode")
            except Exception as e:
                logger.error(f"Censys Domain Mode: Error with key {key[-4:]}: {e}")
        return list(domains)
    else:
        # Reverse mode: require a scope_list of IP addresses.
        if not scope_list:
            logger.error("Reverse lookup mode requires a list of IPs (scope_list) to be provided.")
            return list(domains)

        def query_ip(ip: str, auth: str) -> List[str]:
            local_domains = []
            try:
                with Navigator(debug=logger.level >= 2, timeout=30) as nav:
                    response = nav.request(
                        URL_API,
                        params={'q': f'ip:{ip}', 'per_page': 1000},
                        headers={'Authorization': f'Basic {auth}'},
                        response_type='json',
                        method='GET'
                    )
                    debug_info = nav.get_debug_info()
                    logger.verbose(f"Censys Reverse Mode (IP {ip}) Status Code: {debug_info.get('status_code')}")
                    logger.verbose(f"Censys Reverse Mode (IP {ip}) Final URL: {debug_info.get('final_url')}")
                    logger.verbose(
                        f"Censys Reverse Mode (IP {ip}) Response Preview: {debug_info.get('partial_content')}")
                    if not response:
                        logger.error(f"Censys Reverse Mode (IP {ip}): Empty response")
                        return local_domains
                    if 'result' in response:
                        hits = response['result'].get('hits', [])
                        for hit in hits:
                            for name in hit.get('names', []):
                                # Accept the hostname if it ends with the target domain.
                                if name.lower().endswith(domain.lower()):
                                    local_domains.append(name.lower())
                        logger.debug(f"Censys Reverse Mode (IP {ip}): Found {len(local_domains)} subdomains")
                    else:
                        logger.error(f"Censys Reverse Mode (IP {ip}): Invalid API response structure")
            except Exception as e:
                logger.error(f"Censys Reverse Mode (IP {ip}): Error with key ending {auth[-4:]}: {e}")
            return local_domains

        results = []
        # Use the first API key that returns valid data.
        for key in keys:
            try:
                api_id, api_secret = key.split(':')
                auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
                with ThreadPoolExecutor(max_workers=len(scope_list)) as executor:
                    future_to_ip = {executor.submit(query_ip, ip, auth): ip for ip in scope_list}
                    for future in as_completed(future_to_ip):
                        res = future.result()
                        if res:
                            results.extend(res)
                if results:
                    domains.update(results)
                    logger.debug(f"Censys Reverse Mode: Total found subdomains: {len(domains)} using key {key[-4:]}")
                    break
            except Exception as e:
                logger.error(f"Censys Reverse Mode: Error with key {key[-4:]}: {e}")
        return list(domains)
