from typing import List
import time
try:
    from subcat.navigator import Navigator
except:
    from navigator import Navigator

URL_API = 'https://api.certspotter.com/v1/issuances?domain={}'


def returnDomains(domain: str, logger, conf: str, reverse: bool = False, scope_list: List[str] = None) -> List[str]:
    domains = set()
    max_retries = 3
    retry_delay = 5  # seconds

    # Add CertSpotter specific rate limit
    custom_rate_limit = {'requests': 1, 'period': 2}  # 1 request per 2 seconds

    for attempt in range(max_retries):
        try:
            with Navigator(debug=logger.level >= 2, timeout=30, verify_ssl=False, rate_limit=custom_rate_limit) as nav:
                logger.debug(f"CertSpotter: Attempt {attempt+1}/{max_retries}")
                response = nav.request(URL_API.format(domain), response_type='json', method='GET')
                debug_info = nav.get_debug_info()
                logger.verbose(f"CertSpotter Status Code: {debug_info.get('status_code')}")
                logger.verbose(f"CertSpotter Final URL: {debug_info.get('final_url')}")
                logger.verbose(f"CertSpotter Response Preview: {debug_info.get('partial_content')}")

                if not response:
                    logger.error("CertSpotter: Empty response")
                    if attempt < max_retries - 1:
                        logger.debug(f"CertSpotter: Retrying in {retry_delay} seconds...")
                        time.sleep(retry_delay)
                        retry_delay *= 2  # Exponential backoff
                        continue
                    return []

                for cert in response:
                    for name in cert.get('dns_names', []):
                        if name and domain in name:
                            domains.add(name.lower())
                logger.debug(f"CertSpotter: Found {len(domains)} subdomains")
                break  # Success, exit the retry loop

        except Exception as e:
            logger.error(f"CertSpotter: Error: {e}")
            if attempt < max_retries - 1:
                logger.debug(f"CertSpotter: Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
            else:
                logger.error(f"CertSpotter: Max retries exceeded")

    return list(domains)
