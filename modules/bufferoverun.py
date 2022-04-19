import navigator

URL_API = 'https://dns.bufferover.run/dns?q=.{}'
DOMAINS_LIST = []


def returnDomains(domain):
    olddomain = domain
    req = navigator.Navigator()

    json = req.downloadResponse(URL_API.format(domain), 'JSON', 'GET')

    if json['FDNS_A'] == None:
        return []

    for _ in json['FDNS_A']:
        domainIp, domain = _.split(',')
        if olddomain in req.filterUrl(domain):
            DOMAINS_LIST.append(req.filterUrl(domain))

    return DOMAINS_LIST
