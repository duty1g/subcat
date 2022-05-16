# SubCat
![alt text](https://img.shields.io/github/stars/duty1g/subcat "")
![alt text](https://img.shields.io/github/languages/top/duty1g/subcat "")
![alt text](https://img.shields.io/github/license/duty1g/subcat "")

<img src="https://user-images.githubusercontent.com/3162883/168605639-8a2cb290-38d3-4edb-9587-584d17f4fac3.png" width="60%"/>
<h4>Fast subdomain enumeration tool.</h4>


#
SubCat a subdomain discovery tool that discovers valid subdomains for websites by using passive online sources. It has a simple modular architecture and is optimized for speed. SubCat is built for doing one thing only - passive subdomain enumeration, and it does that very well.

We have designed SubCat to comply with all passive sources licenses, and usage restrictions, as well as maintained a consistently passive model to make it useful to both penetration testers and bug bounty hunters alike.


### Features

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
duty@f:~$ python3 subcat.py -d domain.tld

usage: subcat.py [-h] -d DOMAIN [-sc] [--scope SCOPE] [-t THREADS] [-v]
```

### License

SubCat is made with 🖤 by duty1g
