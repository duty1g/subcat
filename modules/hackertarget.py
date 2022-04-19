import navigator

URL_API = 'https://api.hackertarget.com/hostsearch/?q={}'
DOMAINS_LIST = []


def returnDomains(domain):
    req = navigator.Navigator()

    html = req.downloadResponse(URL_API.format(domain), 'HTML', 'GET').split(',')
    # print(htmlResponse)
    DOMAINS_LIST.append(html[0])

    return DOMAINS_LIST
