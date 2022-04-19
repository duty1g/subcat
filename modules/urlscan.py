import navegador

URL_API = 'https://urlscan.io/api/v1/search/?q=domain:{}'
DOMAINS_LIST = []


# working

def returnDomains(domain):
    req = navegador.Navegador()

    json = req.downloadResponse(URL_API.format(domain), 'JSON', 'GET')

    return DOMAINS_LIST
