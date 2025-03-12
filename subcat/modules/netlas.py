from typing import List
import json
from urllib.parse import urlencode
try:
    from subcat.navigator import Navigator
    from subcat.config import Config
except:
    from navigator import Navigator
    from config import Config

URL_COUNT = "https://app.netlas.io/api/domains_count/"
URL_DOWNLOAD = "https://app.netlas.io/api/domains/download/"


def returnDomains(domain: str, logger, conf: str, reverse: bool = False, scope_list: List[str] = None) -> List[str]:
    domains = set()
    keys = Config(config=conf, logger=logger).read('netlas') or []
    if not keys:
        logger.error("No API key found for Netlas")
        return list(domains)

    for key in keys:
        try:
            with Navigator(debug=logger.level >= 2, timeout=20, verify_ssl=False) as nav:
                query = f"domain:*.{domain} AND NOT domain:{domain}"
                params = {"q": query}
                countUrl = URL_COUNT + "?" + urlencode(params)
                response = nav.request(countUrl, response_type="json", method="GET")
                debug_info = nav.get_debug_info()
                logger.verbose(f"Netlas Count Status Code: {debug_info.get('status_code')}")
                logger.verbose(f"Netlas Count Final URL: {debug_info.get('final_url')}")
                logger.verbose(f"Netlas Count Response Preview: {debug_info.get('partial_content')}")
                if not response or "count" not in response:
                    logger.error("Netlas: Invalid or empty count response")
                    continue
                count = response["count"]
                if count <= 0:
                    logger.debug("Netlas: No domains found for query")
                    continue

                payload = {
                    "q": query,
                    "fields": ["domain"],
                    "source_type": "include",
                    "size": count
                }
                jsonPayload = json.dumps(payload)
                response2 = nav.request(
                    URL_DOWNLOAD,
                    response_type="json",
                    method="POST",
                    data=jsonPayload,
                    headers={
                        "Content-Type": "application/json",
                        "X-API-Key": key
                    }
                )
                debug_info2 = nav.get_debug_info()
                logger.verbose(f"Netlas Download Status Code: {debug_info2.get('status_code')}")
                logger.verbose(f"Netlas Download Final URL: {debug_info2.get('final_url')}")
                logger.verbose(f"Netlas Download Response Preview: {debug_info2.get('partial_content')}")
                if not response2:
                    logger.error("Netlas: Empty download response")
                    continue

                for item in response2:
                    if "data" in item and "domain" in item["data"]:
                        domains.add(item["data"]["domain"].lower())
                logger.debug(f"Netlas: Found {len(domains)} subdomains using key {key[-4:]}")
                if domains:
                    break  # Stop after first key that returns data.
        except Exception as e:
            logger.error(f"Netlas: Error with key ending {key[-4:]}: {e}")
    return list(domains)
