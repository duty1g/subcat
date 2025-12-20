
# SubCat v1.4.0

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
- **Multiple Output Formats:** Export results in TXT, JSON, CSV, and XML formats for easy integration with other tools.
- **Intelligent Caching:** Cache API responses to improve performance and reduce external API calls.
- **Advanced Rate Limiting:** Domain-specific rate limiting to prevent API throttling and ensure reliable results.
- **Reverse Lookup Mode:** Supports reverse lookup to load only modules that handle reverse enumeration (requires a valid IP scope).
- **Custom Module Selection:** Include or exclude specific modules via command-line flags.
- **Enhanced Multi-threading:** Uses 50 concurrent threads by default for rapid processing.
- **AI-Powered Networking:** Powered by `smart-requests-ai` and `ai-urllib4` for intelligent request handling, WAF evasion, and adaptive retries.
- **Gemini AI Integration:** leverages Google's Gemini AI to analyze error responses (e.g., 403 Forbidden) and suggest bypass techniques.


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
  -of {txt,json,csv,xml}, --output-format {txt,json,csv,xml}
                        Output format (default: txt, available: txt, json, csv, xml)
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

AI FEATURES:
  --ai                  Enable AI-powered error analysis for 403/WAF responses

CONFIGURATION:
  -t THREADS, --threads THREADS
                        Number of concurrent threads (default: 50)
  -c CONFIG, --config CONFIG
                        Path to YAML config file (default: config.yaml)
  --no-cache            Disable caching of results
  --cache-ttl CACHE_TTL
                        Time-to-live for cache entries in seconds (default: 86400 = 24 hours)
  --clear-cache         Clear all cached data before running

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
                             v{1.4.0}@duty1g

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

**Export Results in JSON Format:**
   ```console
   subcat -d example.com -o results.json -of json
   ```

**Export Results in CSV Format with Status Codes and IP Addresses:**
   ```console
   subcat -d example.com -o results.csv -of csv -sc -ip
   ```

**Save Results Using Specific Modules:**
   ```console
   subcat -d example.com -s ctrsh,wayback,hackertarget -o example_results.txt
   ```
   This command will:
   - Scan only the example.com domain
   - Use only the crt.sh, Wayback, and HackerTarget modules
   - Save all discovered subdomains to example_results.txt

**Save Results in Different Formats Using Specific Modules:**
   ```console
   # Save as JSON
   subcat -d example.com -s ctrsh,wayback,hackertarget -o example_results.json -of json

   # Save as CSV
   subcat -d example.com -s ctrsh,wayback,hackertarget -o example_results.csv -of csv

   # Save as XML
   subcat -d example.com -s ctrsh,wayback,hackertarget -o example_results.xml -of xml
   ```

**Use Caching with Custom TTL:**
   ```console
   subcat -d example.com --cache-ttl 3600
   ```

**Clear Cache Before Running:**
   ```console
   subcat -d example.com --clear-cache
   ```

**Use AI Analysis for Errors:**
   ```console
   # Default (gemini-2.5-flash)
   subcat -d example.com --ai --api-key YOUR_GEMINI_API_KEY
   
   # Use a specific model (e.g., gemini-1.5-pro)
   subcat -d example.com --ai --api-key YOUR_KEY --ai-model gemini-1.5-pro
   ```
   This will automatically trigger Gemini AI analysis when 403 Forbidden or other error status codes are encountered.
   **Note**: You must provide a valid Gemini API key. Get one from Google AI Studio.


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

## New Features in v1.4.0

### Multiple Output Formats
SubCat now supports exporting results in multiple formats:
- **TXT**: Simple text format with one subdomain per line
- **JSON**: Structured JSON format with detailed information about each subdomain
- **CSV**: CSV format for easy import into spreadsheets and databases
- **XML**: XML format for integration with XML-based tools and workflows

Example:
```console
subcat -d example.com -o results.json -of json
```

### Intelligent Caching
SubCat now includes a caching system to improve performance and reduce API calls:
- Cache API responses to avoid redundant requests
- Configurable cache TTL (time-to-live)
- Commands to manage the cache

Example:
```console
# Use caching with a 1-hour TTL
subcat -d example.com --cache-ttl 3600

# Clear the cache before running
subcat -d example.com --clear-cache

# Disable caching
subcat -d example.com --no-cache
```

### Advanced Rate Limiting
SubCat now includes domain-specific rate limiting to prevent API throttling:
- Automatically applies appropriate rate limits for different API providers
- Handles rate limit responses gracefully
- Implements exponential backoff for failed requests

These features make SubCat more efficient, reliable, and versatile for subdomain enumeration tasks.

### AI Integration
SubCat v1.5.0 introduces AI capabilities:
- **Smart Networking**: Replaced standard `requests` and `urllib3` with `smart-requests-ai` and `ai-urllib4`. These libraries provide intelligent connection pooling and adaptive behavior.
- **Gemini Error Analysis**: When using the `--ai` flag, SubCat uses the Gemini API (via `ai_handler.py`) to analyze HTTP error responses. You can choose your preferred model (e.g., `gemini-1.5-pro` or `gemini-2.5-flash`) using the `--ai-model` flag. This is particularly useful for identifying WAFs (Web Application Firewalls) and getting suggestions for headers or methods to bypass them.


## Version Comparison: v1.4.0 vs v1.5.0

SubCat v1.5.0 represents a major leap forward with the integration of Artificial Intelligence. Here's how it compares to the previous version:

| Feature | SubCat v1.4.0 (Legacy) | SubCat v1.5.0 (AI-Enhanced) |
| :--- | :--- | :--- |
| **Networking Engine** | Standard `requests` & `urllib3` | **`smart-requests-ai` & `ai-urllib4`** (Adaptive, Intelligent Pooling) |
| **WAF Evasion** | Basic user-agent rotation | **AI-Powered Analysis** (Gemini suggests bypass strategies) |
| **Error Handling** | Logs errors (403/429) & continues | **Active Interrogation**: Asks Gemini AI to analyze *why* the request failed |
| **Dependencies** | Standard Python libraries | **AI-Optimized Stack** for modern web scrapping challenges |
| **Intelligence** | Static logic | **Generative AI Integration** (Default: Gemini 2.5 Flash, Configurable via `--ai-model`) |

### Why Upgrade?
- **Smarter Requests**: The new networking stack adapts to server behavior, potentially reducing blocks.
- **Actionable Intel**: Instead of just seeing "403 Forbidden", you get an AI analysis of *how* to potentially bypass it.
- **Future-Proof**: Built on libraries designed for the AI era of web automation.

You can add a **Contributors** section like this, following the style you're using:

---

### Contributors

Special thanks to all the contributors who help make **SubCat** better!
Want to contribute? Pull requests are welcome. 🙌

* [@duty1g](https://github.com/duty1g) — Creator & Maintainer
* [@zinzied](https://github.com/zinzied) — Contributor

---

### License

SubCat is licensed under the [MIT License](LICENSE).
Made with 🖤 by [@duty1g](https://github.com/duty1g)
