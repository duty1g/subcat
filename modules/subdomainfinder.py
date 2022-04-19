import navigator
import re

##bypass crsf token and impossible
##we don't pay this api ;)


URL_API = 'https://subdomainfinder.c99.nl/index.php'
REGEX_CSRF_TOKEN_AND_VALUE = r"<input type=\"hidden\" name=\"(CSRF.*?)\" value=\"(.*?)\"\/>"
POST_DATA = {'': ''}
DOMAINS_LIST = []


def returnDomains(domain):
    req = navigator.Navigator()

    html = req.downloadResponse(URL_API.format(domain), 'HTML', 'GET')

    resultasdosCSRF = re.compile(REGEX_CSRF_TOKEN_AND_VALUE).finditer(html)

    for a in resultasdosCSRF:
        POST_DATA[a[1]] = a[2]

    POST_DATA['domain'] = domain

    # downloadDataFrom = https://subdomainfinder.c99.nl/9617712552/8242470323/1.1.1.1

    # getNewCsrfToken


    """
	if "response_code" in jsonResponse:
		return []

	for _ in jsonResponse['subdomains']:

		DOMAINS_LIST.append(browserRequest.filterUrl(_))
	"""

    return DOMAINS_LIST
