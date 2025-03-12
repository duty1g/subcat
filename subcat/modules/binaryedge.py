from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
try:
    from subcat.navigator import Navigator
    from subcat.config import Config
except:
    from navigator import Navigator
    from config import Config

# Endpoints for BinaryEdge
URL_API_DOMAIN = 'https://api.binaryedge.io/v2/query/domains/subdomain/{}'
URL_API_REVERSE = 'https://api.binaryedge.io/v2/query/domains/ip/{}'
REVERSE_LOOKUP_SUPPORTED = True


def returnDomains(domain: str, logger, conf: str, reverse: bool = False, scope_list: List[str] = None) -> List[str]:
    domains = set()
    keys = Config(config=conf, logger=logger).read('binaryedge') or []
    if not keys:
        logger.error("No API key found for BinaryEdge")
        return list(domains)

    if not reverse:
        # Normal mode: use the domain-based GET endpoint.
        for key in keys:
            try:
                with Navigator(debug=logger.level >= 2, timeout=20) as nav:
                    response = nav.request(
                        URL_API_DOMAIN.format(domain),
                        response_type='json',
                        headers={'X-Key': key},
                        method='GET'
                    )
                    debug_info = nav.get_debug_info()
                    logger.verbose(f"BinaryEdge Status Code: {debug_info.get('status_code')}")
                    logger.verbose(f"BinaryEdge Final URL: {debug_info.get('final_url')}")
                    logger.verbose(f"BinaryEdge Response Preview: {debug_info.get('partial_content')}")
                    if not response:
                        logger.error("BinaryEdge: Empty response")
                        continue
                    if 'events' in response and response['events']:
                        for event in response['events']:
                            # Expect each event to contain a "domain" field.
                            if 'domain' in event and domain.lower() in event['domain'].lower():
                                domains.add(event['domain'].lower())
                        logger.debug(f"BinaryEdge: Found {len(domains)} subdomains using key {key[-4:]}")
                        if domains:
                            break  # Use the first key that returns valid data.
                    else:
                        logger.error("BinaryEdge: Invalid API response structure")
            except Exception as e:
                logger.error(f"BinaryEdge: Error ({key[-4:]}): {e}")
        return list(domains)
    else:
        # Reverse mode: require a scope_list of IP addresses.
        if not scope_list:
            logger.error("Reverse lookup mode requires a list of IPs (scope_list) to be provided.")
            return list(domains)

        def query_ip(ip: str, key: str) -> List[str]:
            local_domains = []
            # Prepare JSON payload for the POST request.
            payload = json.dumps({"filter": {"ipv4": ip}})
            try:
                with Navigator(debug=logger.level >= 2, timeout=20) as nav:
                    response = nav.request(
                        URL_API_REVERSE.format(ip),
                        response_type='json',
                        method='POST',
                        headers={'X-Key': key, 'content-type': 'application/json'},
                        data=payload
                    )
                    debug_info = nav.get_debug_info()
                    logger.verbose(f"BinaryEdge (IP {ip}) Status Code: {debug_info.get('status_code')}")
                    logger.verbose(f"BinaryEdge (IP {ip}) Final URL: {debug_info.get('final_url')}")
                    logger.verbose(f"BinaryEdge (IP {ip}) Response Preview: {debug_info.get('partial_content')}")
                    if not response:
                        logger.error(f"BinaryEdge (IP {ip}): Empty response")
                        return local_domains
                    if 'events' in response and response['events']:
                        for event in response['events']:
                            # Extract domain from event.
                            event_domain = event.get('domain', '').lower()
                            if event_domain and event_domain.endswith(domain.lower()):
                                local_domains.append(event_domain)
                        logger.debug(f"BinaryEdge (IP {ip}): Found {len(local_domains)} domains using key {key[-4:]}")
                    else:
                        logger.error(f"BinaryEdge (IP {ip}): Invalid API response structure")
            except Exception as e:
                logger.error(f"BinaryEdge (IP {ip}): Error with key ending {key[-4:]}: {e}")
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
                logger.debug(f"BinaryEdge (reverse): Total found domains: {len(domains)} using key {key[-4:]}")
                break
        return list(domains)
