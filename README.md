# Subdomino
![Image of Subdomino](http://image.noelshack.com/fichiers/2016/39/1475404267-capture-d-ecran-de-2016-10-02-17-28-57.png)
```
Warning : Need to be run as root in order to ping a domain, due to the socket use !
```

## Dependencies 
* Ping-v0.2 - pip install ping
* Argparse  - pip install argparse

## Description and How to
**Features:** 
* Bruteforce subdomains with file 'names.txt'
* Detect subdomains using dork in Google
* Auto ping of every detected subdomains
* Generate report for every subdomains
* NMAP of every detected subdomains
* Advanced scan with custom rules to detect IOV (indicator of vulnerability)

**How to use it:** 
```
sudo python Subdomino.py --domain google.com (--nmap) (--google)
```