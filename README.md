
# SubCat v1.3.1

![alt text](https://img.shields.io/github/stars/duty1g/subcat "")
![alt text](https://img.shields.io/github/languages/top/duty1g/subcat "")
![alt text](https://img.shields.io/github/license/duty1g/subcat "")
<a href="https://twitter.com/duty_1g"><img src="https://img.shields.io/twitter/follow/duty_1g.svg?logo=twitter"></a>


<p align="center"><img src="https://user-images.githubusercontent.com/3162883/168605639-8a2cb290-38d3-4edb-9587-584d17f4fac3.png#gh-dark-mode-only" width="60%"/>
  <img src="https://user-images.githubusercontent.com/3162883/169028346-3151e07e-ea94-4911-8009-942a5f384c77.png#gh-light-mode-only" width="60%"/>
</p>
<h4 align="center">Fast subdomain enumeration tool.</h4>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#Install">Install</a> •
  <a href="#post-installation">Post Installation</a> •
  <a href="#Usage">Usage</a> •
  <a href="#running-subcat">Running SubCat</a>
  <a href="#available-modules">Available Modules</a>
</p>

#
SubCat is a powerful subdomain discovery tool that passively aggregates data from a variety of online sources to identify valid subdomains for websites. Designed with a modular and efficient architecture, SubCat is ideal for penetration testers, bug bounty hunters, and security researchers.

Built to comply with licensing and usage restrictions of its passive sources, SubCat ensures minimal impact on target systems while delivering in-depth subdomain intelligence.


## Features

<img width="1000" alt="demo" src="https://github.com/user-attachments/assets/1de8c659-f35b-44ce-9aa8-c0437717591b">

- **Fast Enumeration:** Leverages a high-performance resolution and wildcard elimination module.
- **Curated Passive Sources:** Gathers subdomains from trusted online sources to maximize coverage.
- **Lightweight & Efficient:** Optimized for speed with minimal resource consumption.
- **STDIN/STDOUT Integration:** Seamlessly integrate with other tools and workflows.
- **IP Scope Filtering:** Filter results by IP addresses using a provided scope (CIDR or file-based).
- **Detailed Output:** Options to display HTTP status codes, page titles, IP addresses, and technology detection.
- **Reverse Lookup Mode:** Supports reverse lookup to load only modules that handle reverse enumeration (requires a valid IP scope).
- **Custom Module Selection:** Include or exclude specific modules via command-line flags.
- **Enhanced Multi-threading:** Uses 50 concurrent threads by default for rapid processing.


## Install
```
# Linux, Windows, MacOS
pip install subcat
```

## Post Installation

Before querying third-party services, configure your API keys in the `config.yaml` file.  
 
By default, SubCat looks for the configuration file in your user's home directory under `~/.subcat/config.yaml`. You can also specify a custom config path using the `-c` or `--config` option.  

Not all modules require an API key, but the following sources do:

- **BinaryEdge**
- **Virustotal**
- **SecurityTrails**
- **Shodan**
- **Bevigil**
- **Chaos**
- **DNSDumpster**
- **Netlas**
- **DigitalYama**
- **Censys**
- **AlienVault**
- **CertSpotter**
- **URLScan** (for advanced usage)


An example provider config file 

```yaml

binaryedge:
  - e3a2f1c4-9d2b-47f3-a1e2-4b8d7f0a1c2e
virustotal:
  - b1e2d3c4f5a6978877665544332211ffeeddccbbaa99887766554433221100ff
securitytrails:
  - X7a9B2c4D6e8F0g1H3i5J7k9L1m3N5o7
  - P8q6R4s2T0u8V6w4X2y0Z8a6B4c2D0e2
shodan:
  - M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6A7b8
bevigil:
  - F1g2H3i4J5k6L7m8
chaos:
  - d2c4b6a8-90ef-12ab-34cd-56ef78ab90cd
dnsdumpster:
  - c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4
  - e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5
netlas:
  - Z1x2C3v4B5n6M7a8S9d0F1g2H3j4K5l6
digitalyama:
  - Q1w2E3r4T5y6U7i8O9p0


```

## Usage

```console
subcat -h
```
This will display help for the tool. Here are all the switches it supports.

```yaml
INPUT:
  -d DOMAIN, --domain DOMAIN
                        Target domain to scan
  -l LIST, --list LIST  File containing list of domains
  --scope SCOPE         IP scope filter: provide either a file containing CIDR ranges or a single IP/CIDR string (e.g., '8.8.8.8' or  
                        '8.8.4.0/24'). This filter is required when reverse lookup is enabled.

OUTPUT:
  -o OUTPUT, --output OUTPUT
                        Output file
  -title, --title       Show page titles
  -ip, --ip             Resolve IP addresses
  -sc, --status-code    Show HTTP status codes
  --up                  Show only domains that are up (exclude TIMEOUT)
  -td, --tech           Show detected technologies
  -nc, --no-colors      Disable colored output in console

FILTERS:
  -mc MATCH_CODES, --match-codes MATCH_CODES
                        Comma separated list of HTTP status codes to filter (e.g., 200,404)

SOURCE:
  -ls                   List available modules and exit
  -s SOURCES, --sources SOURCES
                        Specific sources to use for discovery (comma-separated, e.g., crtsh,wayback)
  -es EXCLUDE_SOURCES, --exclude-sources EXCLUDE_SOURCES
                        Sources to exclude from enumeration (comma-separated, e.g., alienvault,crtsh)
  -r, --reverse         Enable reverse lookup mode for enumeration (loads only modules supporting reverse lookup). Requires --scope   
                        to be provided.

CONFIGURATION:
  -t THREADS, --threads THREADS
                        Number of concurrent threads (default: 50)
  -c CONFIG, --config CONFIG
                        Path to YAML config file (default: config.yaml)

DEBUG:
  -v, --verbose         Increase verbosity level (-v, -vv, -vvv)
  -silent, --silent     Suppress all output except results
  -h, --help            Show this help message and exit
```

## Running SubCat
Here are several examples to help you get started:

**Scan a Single Domain:**
   ```console
subcat -d hackerone.com --sc --title --tech --up                                                                

 
                              ;            ;                  
                            ρββΚ          ;ββΝ                
                          έΆχββββββββββββββββββΒ              
                        ;ΣΆχΜ΅΅ΫΝββββββββ Ϋ΅ΫβββΝ            
                       όΆΆχβ   Ά   ββββ΅  Ά΅  βββββ           
                      χΆΆΆφβΒ; Ϋ΅;έββββΒ; Ϋ΅ ρββββββ          
                      ΆΆΆΆδβββββββββ;χββββββμβββββββ          
                      ΪχχχχΧβββββββββββββββββββθθθθΚ          
                     ·ϊβθβζ  Ϊθθβββββββββββββββμ ;όβΫ΅        
                      ·΅   ΅ΫΫΫΆΆθβββββββββθθΫ΅   ΅Ϋ΅         
                              ;ΣΆθββββΒΝρρρμ                  
                             ;ΣΆΆβββββββββββμ
         ▄∞∞∞∞∞▄, ╒∞∞▄   ∞∞▄ ▄∞∞∞∞∞∞▄   ,▄∞∞∞∞▄      ▄∞∞4▄  ╒∞∞∞∞∞∞∞▄,
        ▐▄ ═▄▄▄ ▐█▐ ,▀  j' █▌█  ▄▄▄ ▀█▌█▀ ╓▄▄  ▀▄  ¡█  , ▐█ ▐▄▄▄  ▄▄██
        ▐▄ `'""▀██▐  █▌ j  █▌█  `"" ▄█▌█ ▐█▀`▀▄██' M  $██  █, `█ ▐█```
        j▀▀███▌ ▐█▐  ▀▌▄█  ▀▀█ ▐███  █▌▄ ▀█▄▄▀ ▐█M▀.       ▀█▄.▀ J▀
        ╚▄,,¬¬⌐▄█▌ ▀▄,,, ▄██ █,,,,,▓██▌ ▀▄,,,,▄█╩j▌,██▀▀▀▀▌,█▌`█,▐█
          ▀▀▀▀▀▀▀    ▀▀▀▀▀▀ ""▀▀▀▀▀▀      ▀▀▀""`  ▀▀▀     ▀▀▀   ▀▀▀
                       ΅qΆΆΆΆβββββββββββββββββββββΡ΅  
                          ΫθΆΆΆββββββββββββββββΡ΅         
                              ΅ΫΫΫ΅ΝNNΝΫΫΫΐ΅Ϋ      
                             v{1.3.0#dev}@duty1g

[07:43:51][INF]: Starting enumeration for hackerone.com
[07:43:51][INF]: Loaded 19 modules
https://mta-sts.managed.hackerone.com [Page not found &middot; GitHub] [Fastly,GitHub Pages]
https://www.hackerone.com [HackerOne | #1 Trusted Securit] [Google Tag Manager,Drupal,HSTS,Cloudflare,Pantheon,PHP,Fastly,MariaDB,Nginx]
https://gslink.hackerone.com [404 Not Found] [Nginx,Amazon CloudFront,Amazon Web Services]
https://mta-sts.hackerone.com [Page not found &middot; GitHub] [GitHub Pages,Fastly]
https://api.hackerone.com [HackerOne API] [Algolia,HSTS,Cloudflare]
http://resources.hackerone.com [Sorry, no Folders found.] [Amazon Web Services]
https://hackerone.com [HackerOne | #1 Trusted Securit] [Cloudflare,Drupal,Google Tag Manager,HSTS,Pantheon,PHP,Fastly,MariaDB,Nginx]  
https://mta-sts.forwarding.hackerone.com [Page not found &middot; GitHub] [Fastly,GitHub Pages]
https://docs.hackerone.com [HackerOne Help Center] [Cloudflare,HSTS]
https://support.hackerone.com [Sign into : HackerOne Support ] [HSTS,Envoy,Cloudflare,HTTP/3]
[07:44:00][INF]: Completed with 23 subdomains for hackerone.com in 9 seconds 58 milliseconds
   ```

**Pipe Domains from a File with IP Resolution and HTTP Status Codes:**
   ```console
   cat domains.txt | subcat -ip -sc
   ```

**Run with Reverse Lookup Mode (Requires IP Scope):**
   ```console
   subcat -d example.com --scope 8.8.8.0/24 -r
   ```

**Scan a Domain and Save the Output to a File (Verbose Mode):**
   ```console
   subcat -d hackerone.com -o output.txt -v
   ```

**Integrate with HTTPx for Further Processing or any other tool:**
   ```console
   echo hackerone.com | subcat -silent -td -title | httpx -silent
   ```

**Scan Multiple Domains from a List:**
   ```console
   subcat -l domains.txt
   ```

**Custom Module Selection:**
   ```console
   subcat -d example.com -s dnsdumpster,virustotal,urlscan -es digitalyama,anubis
   ```


## Available Modules

SubCat currently supports the following modules for passive subdomain discovery:

- dnsdumpster
- digitalyama
- virustotal
- binaryedge
- chaos
- bevigil
- dnsarchive
- netlas
- wayback
- shodan
- securitytrails
- urlscan
- ctrsh
- threatcrowd
- anubis
- censys
- alienvault
- hackertarget
- certspotter

SubCat's modular architecture is designed for flexibility and ease of extension. 

If you have an idea for a new module or want to contribute improvements, feel free to submit a pull request. Your contributions help make SubCat even better!


### License

SubCat is made with 🖤 by duty1g

<a href="https://www.buymeacoffee.com/duty1g" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>