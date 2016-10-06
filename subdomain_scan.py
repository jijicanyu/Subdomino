#!/usr/bin/python
# -*- coding: utf-8 -*-
import re
import os
import sys
import argparse
import socket
import requests
import signal
import multiprocessing
from ping import *
from subdomain_enum import *

# Scan a subdomain to determine if it's online
def scan_subdomain(dest_addr, timeout = 1, count = 1, psize = 64):
    mrtt = None
    artt = None
    lost = 0
    plist = []
    dest_addr = dest_addr.replace('https://','').replace('http://','')

    for i in xrange(count):
        try:
            delay = do_one(dest_addr, timeout, psize)
        except socket.gaierror, e:
            return False

        if delay != None:
            delay = delay * 1000
            plist.append(delay)

    # Find lost package percent
    percent_lost = 100 - (len(plist) * 100 / count)

    # Find max and avg round trip time
    if plist:
        mrtt = max(plist)
        artt = sum(plist) / len(plist)


	if( percent_lost  == 0 ):
		return True
	else:
		# Do not show failed host
		return False

# Start a nmap for every subdomains and store the result
def nmap_subdomains(online_subdmn,nmap):
	if (nmap):
		print "\n[+] NMAP Subdomains"
		for subdmn in online_subdmn:
			# Execute nmap scan
			clean_url = subdmn.replace('https://','').replace('http://','')
			print " NMAP for "+clean_url
			os.system('nmap -F '+clean_url+' >> reports/'+subdmn.replace('://','_'))

			# Should be open with a simple user
			uid = int(os.environ.get('SUDO_UID'))
			gid = int(os.environ.get('SUDO_GID'))
			os.chown('reports/'+subdmn.replace('://','_'), uid, gid)

