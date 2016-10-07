# Subdomino
![Image of Subdomino](http://image.noelshack.com/fichiers/2016/39/1475404267-capture-d-ecran-de-2016-10-02-17-28-57.png)
An application that enumerates subdomains, and scan them with different rules
```
Warning : Need to be run as root in order to ping a domain, due to the socket use !
```

## Dependencies 
* Ping-v0.2 - pip install ping
* Argparse  - pip install argparse


## Features
* Bruteforce subdomains with file 'names.txt' or custom
* Detect subdomains using dork in Google
* Auto ping of every detected subdomains
* Generate report for every subdomains
* NMAP of every detected subdomains
* Advanced scan with custom rules to detect IOV (indicator of vulnerability)


## How to use to enumerate online subdomains, and launch detection rule-based
```
sudo python Subdomino.py --domain google.com (--nmap) (--google) (--names big_names.txt) (--threads 20)
```
The options are:
* nmap   : launch a fast nmap on every discovered subdomains
* google : search for subdomain using google dork
* names  : allow you to use a custom file to bruteforce subdomains
* threads: number of pools you want to use for the multiprocessing bruteforce


## How to add new rules
You need to add an entry in **"rules.txt"** like this
```
name: Name of the rule
rule: Put here the rule you want to match
desc: Description of the rule
```

You can use the following rules pattern:
* is_string_page
* is_string_header
* regex_match_page
* regex_match_header

You can also chain several rules with **AND** operator like this
```
rule: is_string_page("hash") AND regex_match_page("jquery.*?(1).([0-7]).([0-9]+)")
```