# -*- coding: utf-8 -*-
import warnings
import signal
import threading
import multiprocessing
import ipaddress
import time
import os
import sys
import socket
import argparse
from datetime import datetime

import navigator

# load navigator Modules
from modules import *

warnings.filterwarnings("ignore")

domainList = []
scopeList = []

animation = "⢿⣻⣽⣾⣷⣯⣟⡿"
reset = '\033[m'
light_grey = '\033[37m'
dark_grey = '\033[90m'
red = '\033[31m'
bold = '\033[1m'
yellow = '\033[93m'


def banner():
    head = ''' 
\t                      {1};            ;                  
\t                    {0}ρ{1}ββΚ          ;ββΝ                
\t                  {0}έΆ{1}χββββββββββββββββββΒ              
\t                {0};ΣΆ{1}χΜ΅΅ΫΝββββββββ Ϋ΅΅ΫβββΝ            
\t               {0}όΆΆχ{1}β   {2}Ά{1}   ββββ΅  {2}Ά΅{1}  βββββ           
\t              {0}χΆΆΆφ{1}βΒ; {2}Ϋ΅{1};έββββΒ; {2}Ϋ΅{1} ρββββββ          
\t              {0}ΆΆΆΆδ{1}βββββββββ{0};χ{1}ββββββμβββββββ          
\t              {0}ΪχχχχΧ{1}βββββββββββββββββββθθθθΚ          
\t             {0}·ϊβθβζ  {1}Ϊθθβββββββββββββββμ ;όβΫ΅        
\t              {0}·΅   ΅ΫΫΫΆΆθ{1}βββββββββθθΫ΅   ΅Ϋ΅         
\t                      {0};ΣΆθ{1}ββββΒΝρρρμ                  
\t                     {0};ΣΆΆ{1}βββββββββββμ{3}
\t ▄∞∞∞∞∞▄, ╒∞∞▄   ∞∞▄ ▄∞∞∞∞∞∞▄   ,▄∞∞∞∞▄      ▄∞∞4▄  ╒∞∞∞∞∞∞∞▄,
\t▐▄ ═▄▄▄ ▐█▐ ,▀  j' █▌█  ▄▄▄ ▀█▌█▀ ╓▄▄  ▀▄  ¡█  , ▐█ ▐▄▄▄  ▄▄██
\t▐▄ `'""▀██▐  █▌ j  █▌█  `"" ▄█▌█ ▐█▀`▀▄██' M  $██  █, `█ ▐█```
\tj▀▀███▌ ▐█▐  ▀▌▄█  ▀▀█ ▐███  █▌▄ ▀█▄▄▀ ▐█M▀.       ▀█▄.▀ J▀
\t╚▄,,¬¬⌐▄█▌ ▀▄,,, ▄██ █,,,,,▓██▌ ▀▄,,,,▄█╩j▌,██▀▀▀▀▌,█▌`█,▐█
\t  ▀▀▀▀▀▀▀    ▀▀▀▀▀▀ ""▀▀▀▀▀▀      ▀▀▀""`  ▀▀▀     ▀▀▀   ▀▀▀
\t               {0}΅qΆΆΆΆ{1}ββ {2}V1.0{0}@{3}duty1g{1} ββββββΡ΅  
\t                  {0}ΫθΆΆΆ{1}ββββββββββββββββΡ΅         
\t                      {1}΅ΫΫΫΫΝNNΝΫΫΫΐ΅΅                          
\t                            {4}
\n'''
    head = head.format(light_grey, dark_grey, red, yellow, reset)
    os.system('cls' if os.name == 'nt' else 'clear')
    sys.stdout.write(bold + head + reset)


class SubCat:
    def __init__(self, domain, threads=50, scope=False, debug=False, statusCode=False, nip=False):
        self.domain = domain
        self.threads = threads
        self.scope = scope
        self.debug = debug
        self.statusCode = statusCode
        self.nip = nip
        self.scopeList = []
        if self.scope:
            self._log('Loading scope list')
            with open(self.scope) as f:
                lines = f.readlines()
            self._log('Resolving scope list to IPV4')
            for line in lines:
                for ip in ipaddress.IPv4Network(line.strip()):
                    self.scopeList.append(str(ip))

    def fetchWorker(self, q):
        domainAndIp = q
        ipDomain = self.getIP(domainAndIp)
        domainReturn = domainAndIp
        if self.statusCode:
            try:
                statusCode = navigator.Navigator().downloadResponse('http://{}'.format(domainAndIp), 'STATUS',
                                                                    'GET').status_code
            except:
                statusCode = 'TIMEOUT'

            if statusCode is not None:
                domainReturn += ' - ({})'.format(statusCode)

        if self.scope:
            if ipDomain in self.scopeList:
                if not self.nip:
                    domainReturn += ' {}'.format(ipDomain)
                else:
                    domainReturn += ''
                print(domainReturn)
        else:
            if not self.nip:
                domainReturn += ' {}'.format(ipDomain)
            else:
                domainReturn += ''
            print(domainReturn)

    def init_worker(self):
        signal.signal(signal.SIGINT, signal.SIG_IGN)

    def fetchDomains(self, sublist):
        try:
            pool = multiprocessing.Pool(self.threads, initializer=self.init_worker)
            pool.map(self.fetchWorker, sublist)
            pool.close()
            pool.join()
        except KeyboardInterrupt:
            self._warn('Shutting down...')
            pool.terminate()

    def fetch(self):
        self._log('loading Modules')
        threading.Thread(target=self.queue, args=[modules.alienvault.returnDomains(self.domain)]).start()
        threading.Thread(target=self.queue, args=[modules.wayback.returnDomains(self.domain)]).start()
        threading.Thread(target=self.queue, args=[modules.hackertarget.returnDomains(self.domain)]).start()
        threading.Thread(target=self.queue, args=[modules.ctrsh.returnDomains(self.domain)]).start()
        threading.Thread(target=self.queue, args=[modules.certspotter.returnDomains(self.domain)]).start()
        threading.Thread(target=self.queue, args=[modules.bufferoverun.returnDomains(self.domain)]).start()
        threading.Thread(target=self.queue, args=[modules.threatcrowd.returnDomains(self.domain)]).start()

    def getDomains(self):
        th = threading.Thread(target=self.fetch)
        th.daemon = True
        th.start()
        load = 1
        now = datetime.now()
        current_time = now.strftime("%H:%M:%S")
        try:
            while th.is_alive():
                sys.stdout.write("\r" + '[' + '\033[36m' + current_time + '\033[m' + '] [' + '\033[36m' + 'INFO' + '\033[m' + ']:' + "\033[1m\033[31m\033[0m\033[32m" + animation[
                    load % len(animation)] + '\033[1m\033[31m\033[32m extracting subdomains : ' + str(
                    len(domainList)) + '\033[0m')
                sys.stdout.flush()
                load += 1
                time.sleep(0.1)
            sys.stdout.write(
                '\r[' + '\033[36m' + current_time + '\033[m' + '] [' + '\033[36m' + 'INFO' + '\033[m' + ']:' + "\033[1m\033[1m\033\033[32m extracted subdomains : \033[33m" + str(
                    len(domainList)) + "  \033[0m")
            sys.stdout.flush()
            print('\n')
            th.join()
        except KeyboardInterrupt:
            self._warn('Shutting down...')
            exit(0)

    def _log(self, *args):
        if self.debug:
            now = datetime.now()
            current_time = now.strftime("%H:%M:%S")
            print(
                '[' + '\033[36m' + current_time + '\033[m' + '] [' + '\033[33m' + 'DEBUG' + '\033[m' + ']:' + '\033[m' + ' {0}'.format(
                    *args))

    def _info(self, *args):
        now = datetime.now()
        current_time = now.strftime("%H:%M:%S")
        print(
                '[' + '\033[36m' + current_time + '\033[m' + '] [' + '\033[36m' + 'INFO' + '\033[m' + ']:' + '\033[m' + ' {0}'.format(
                    *args))

    def _warn(self, *args):
        now = datetime.now()
        current_time = now.strftime("%H:%M:%S")
        print(
                '\n\033[m[' + '\033[36m' + current_time + '\033[m' + '] [' + '\033[31m' + 'WARNING' + '\033[m' + ']:' + '\033[m' + ' {0}'.format(
                    *args))

    def getIP(self, subdomain):
        try:
            return socket.gethostbyname(subdomain)
        except:
            return '0.0.0.0'

    def queue(self, listOld):
        global domainList
        for _ in listOld:
            domainList.append(_)
        domainList = list(dict.fromkeys(domainList))


def argParserCommands():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--domain', dest="domain", help='google.com',
                        required=False)
    parser.add_argument('-l', default=(None if sys.stdin.isatty() else sys.stdin), type=argparse.FileType('r'), dest="domainList", help='list.txt',
                        required=False)
    parser.add_argument('-sc', '--status-code', dest="statusCode",
                        help='Show response status code', default=False,
                        action="store_true")
    parser.add_argument('--scope', dest="scope",
                        help='Show only in cope', default=False)
    parser.add_argument('-t', '--threads', type=int, dest="threads", default=50, help="50")
    parser.add_argument('-nip', '--no-ip', dest="nip", help='Do not respolve IP', default=False,
                        action="store_true")
    parser.add_argument('-v', dest="verbose", help='Verbose Mode', default=False,
                        action="store_true")

    return parser.parse_args()


if __name__ == "__main__":
    banner()

    args = argParserCommands()
    if args.domainList and args.domain is None:
        dlist = args.domainList.read()
        for d in dlist.split('\n'):
            subcat = SubCat(d.strip(), args.threads, args.scope, args.verbose, args.statusCode, args.nip)
            subcat.getDomains()
            subcat.fetchDomains(domainList)
    elif args.domain and args.domainList is None:
        subcat = SubCat(args.domain, args.threads, args.scope, args.verbose, args.statusCode, args.nip)
        subcat.getDomains()
        subcat.fetchDomains(domainList)
    elif args.domain and args.domainList:
        dlist = args.domainList.read()
        for d in dlist.split('\n'):
            subcat = SubCat(d.strip(), args.threads, args.scope, args.verbose, args.statusCode, args.nip)
            subcat.getDomains()
            subcat.fetchDomains(domainList)
    else:
        print(" no domain or list provided")
