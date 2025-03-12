from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed
try:
    from subcat.navigator import Navigator
    from subcat.config import Config
except:
    from navigator import Navigator
    from config import Config

URL_API_DOMAIN = 'https://www.virustotal.com/vtapi/v2/domain/report'
URL_API_IP = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
REVERSE_LOOKUP_SUPPORTED = True


def returnDomains(domain: str, logger, conf: str, reverse: bool = False, scope_list: List[str] = None) -> List[str]:
    domains = set()
    keys = Config(config=conf, logger=logger).read('virustotal') or []
    if not keys:
        logger.error("No API key found for VirusTotal")
        return list(domains)

    # Normal mode: use the domain report API.
    if not reverse:
        api_url = URL_API_DOMAIN
        params = {'domain': domain}
        for key in keys:
            try:
                params['apikey'] = key
                with Navigator(debug=logger.level >= 2, timeout=20, verify_ssl=False) as nav:
                    response = nav.request(
                        api_url,
                        response_type='json',
                        method='GET',
                        params=params
                    )
                    debug_info = nav.get_debug_info()
                    logger.verbose(f"VirusTotal Status Code: {debug_info.get('status_code')}")
                    logger.verbose(f"VirusTotal Final URL: {debug_info.get('final_url')}")
                    logger.verbose(f"VirusTotal Response Preview: {debug_info.get('partial_content')}")
                    if debug_info.get('status_code') != 200:
                        logger.error(
                            f"VirusTotal: Received status code {debug_info.get('status_code')} for key {key[-4:]}")
                        continue
                    if not response:
                        logger.error("VirusTotal: Empty response")
                        continue
                    if 'subdomains' in response and response['subdomains']:
                        for s in response['subdomains']:
                            if s and domain.lower() in s.lower():
                                domains.add(s.lower())
                        logger.debug(f"VirusTotal: Found {len(domains)} subdomains using key {key[-4:]}")
                    else:
                        logger.error("VirusTotal: Invalid API response structure or empty response")
                    if domains:
                        break  # Stop after the first key that returns valid data.
            except Exception as e:
                logger.error(f"VirusTotal: Error with key ending {key[-4:]}: {e}")
        return list(domains)
    else:
        # Reverse mode: ensure a scope_list is provided.
        if not scope_list:
            logger.error("Reverse lookup mode requires a list of IPs (scope_list) to be provided.")
            return list(domains)

        # Define a helper function to query a given IP concurrently.
        def query_ip(ip: str, key: str) -> List[str]:
            local_domains = []
            params = {'ip': ip, 'apikey': key}
            try:
                with Navigator(debug=logger.level >= 2, timeout=20, verify_ssl=False) as nav:
                    response = nav.request(
                        URL_API_IP,
                        response_type='json',
                        method='GET',
                        params=params
                    )
                    debug_info = nav.get_debug_info()
                    logger.verbose(f"VirusTotal Status Code (IP {ip}): {debug_info.get('status_code')}")
                    logger.verbose(f"VirusTotal Final URL (IP {ip}): {debug_info.get('final_url')}")
                    logger.verbose(f"VirusTotal Response Preview (IP {ip}): {debug_info.get('partial_content')}")
                    if debug_info.get('status_code') != 200:
                        logger.error(
                            f"VirusTotal (IP {ip}): Received status code {debug_info.get('status_code')} for key {key[-4:]}")
                        return local_domains
                    if not response:
                        logger.error(f"VirusTotal (IP {ip}): Empty response")
                        return local_domains
                    if 'resolutions' in response and isinstance(response['resolutions'], list):
                        for rec in response['resolutions']:
                            hostname = rec.get('hostname', '').lower()
                            if hostname and hostname.endswith(domain.lower()):
                                local_domains.append(hostname)
                        logger.debug(
                            f"VirusTotal (IP {ip}): Found {len(local_domains)} subdomains using key {key[-4:]}")
                    else:
                        logger.error(f"VirusTotal (IP {ip}): Invalid API response structure or empty response")
            except Exception as e:
                logger.error(f"VirusTotal (IP {ip}): Error with key ending {key[-4:]}: {e}")
            return local_domains

        # Use the first API key that returns valid data for any IP.
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
                logger.debug(f"VirusTotal (reverse): Total found subdomains: {len(domains)} using key {key[-4:]}")
                break  # Stop after the first key that returns valid data.
        return list(domains)
