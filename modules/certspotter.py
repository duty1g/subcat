from typing import List
from navigator import Navigator

URL_API = 'https://api.certspotter.com/v1/issuances?domain={}'


def returnDomains(domain: str, logger, conf: str) -> List[str]:
    domains = set()
    try:
        with Navigator(debug=logger.level >= 2, timeout=20, verify_ssl=False) as nav:
            response = nav.request(URL_API.format(domain), response_type='json', method='GET')
            debug_info = nav.get_debug_info()
            logger.verbose(f"CertSpotter Status Code: {debug_info.get('status_code')}")
            logger.verbose(f"CertSpotter Final URL: {debug_info.get('final_url')}")
            logger.verbose(f"CertSpotter Response Preview: {debug_info.get('partial_content')}")
            if not response:
                logger.error("CertSpotter: Empty response")
                return []
            for cert in response:
                for name in cert.get('dns_names', []):
                    if name and domain in name:
                        domains.add(name.lower())
            logger.debug(f"CertSpotter: Found {len(domains)} subdomains")
    except Exception as e:
        logger.error(f"CertSpotter: Error: {e}")
    return list(domains)
