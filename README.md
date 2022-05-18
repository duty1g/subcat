
# SubCat

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
  <a href="#Usage">Usage</a> •
  <a href="#running-subcat">Running SubCat</a>
</p>

#
SubCat a subdomain discovery tool that discovers valid subdomains for websites by using passive online sources. It has a simple modular architecture and is optimized for speed. SubCat is built for doing one thing only - passive subdomain enumeration, and it does that very well.

We have designed SubCat to comply with all passive sources licenses, and usage restrictions, as well as maintained a consistently passive model to make it useful to both penetration testers and bug bounty hunters alike.


### Features
[![asciicast](https://asciinema.org/a/Jy6XBQZ9m5CYfCwaLEpE5vqNL.svg)](https://asciinema.org/a/Jy6XBQZ9m5CYfCwaLEpE5vqNL)

<img width="592" alt="Screen Shot 2022-05-18 at 12 40 02 PM" src="https://user-images.githubusercontent.com/3162883/169030524-73087bb0-c6e6-4a64-9752-cffa5b3cadb6.png">

- Fast and powerful resolution and wildcard elimination module
- **Curated** passive sources to maximize results
- Optimized for speed, very fast and **lightweight** on resources
- **STDIN/OUT** support for integrating in workflows
- Scope limitation based on given IP ranges list 

### Install
```
# Linux, Windows, MacOS
pip3 install -r requirements.txt
```

### Usage

```console
duty@f:~$ python3 subcat.py -h
```
This will display help for the tool. Here are all the switches it supports.

```yaml
Flags:
INPUT:
   -d --domain string  domains to find subdomains for
   -l string[] | stdin  list of domains to find subdomains for
   --scope string Show only in cope

OUTPUT:
   -sc, --status-code string       Show response status code
   -nip --no-ip       Do not respolve IP
   
CONFIG:
   -t --threads       Number of threads used

DEBUG:
   -v        show verbose output
```

### Running SubCat
```console
cat domains | python3 subcat.py
```

```console
python3 subcat.py -d hackerone.com


 
	                      ;            ;                  
	                    ρββΚ          ;ββΝ                
	                  έΆχββββββββββββββββββΒ              
	                ;ΣΆχΜ΅΅ΫΝββββββββ Ϋ΅΅ΫβββΝ            
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
	               ΅qΆΆΆΆββ V1.0@duty1g ββββββΡ΅  
	                  ΫθΆΆΆββββββββββββββββΡ΅         
	                      ΅ΫΫΫΫΝNNΝΫΫΫΐ΅΅                          
	                            

[12:37:13] [INFO]: extracted subdomains : 14  

docs.hackerone.com 185.199.111.153
support.hackerone.com 104.16.51.111
3d.hackerone.com 0.0.0.0
mta-sts.forwarding.hackerone.com 185.199.110.153
api.hackerone.com 104.16.99.52
www.hackerone.com 104.16.99.52
events.hackerone.com 0.0.0.0
a.ns.hackerone.com 162.159.0.31
b.ns.hackerone.com 162.159.1.31
resources.hackerone.com 3.98.63.202
mta-sts.managed.hackerone.com 185.199.111.153
gslink.hackerone.com 13.224.226.45
mta-sts.hackerone.com 185.199.111.153
hackerone.com 104.16.99.52

```

To run the tool on a target, just use the following command.
### License

SubCat is made with 🖤 by duty1g
