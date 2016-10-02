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

# Initialize the global variable
def init_enumeration(nmap_arg):
	# Storing all the subdomains
	global online_subdmn
	online_subdmn = []

	# Handle nmap scan for every subdomain
	global nmap
	if (nmap_arg):
		print "[OPTION] Nmap Scan enabled"
	else:
		print "[OPTION] Nmap Scan disabled"
	nmap = nmap_arg


# CTRL+C Handler
def signal_handler(signal, frame):
	enf_of_software()

	
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
            # Do not show failed host
            break

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
		print "\033[92mUP - \033[0m" + dest_addr
		return True
	else:
		# Do not show failed host
		return False


# Generate a list of potential subdomain
def brute_with_file(domain):
	print "\n[+] Brute subdomain from names.txt ..."
	# This interruption will manage CTRL+C in different states
	signal.signal(signal.SIGINT, signal_handler)

	with open('names.txt','r') as dict_file:
		dict_file = dict_file.readlines()
		
		# Determine online subdomain
		for index,subdmn in enumerate(dict_file):
			clean_url = "http://"+subdmn.strip()+"."+domain
			if not clean_url in online_subdmn and scan_subdomain(clean_url):
				online_subdmn.append(clean_url)

	
# Function for the multiprocessing crawl
def crawl_google_for_subdomain_extract(stuff_to_get):
  global google
  stuff_got = []
  
  for thing in stuff_to_get:
    stuff_got.append( requests.get(google + thing).text )

  return stuff_got


# Extract subdomain from google results
def crawl_google_for_subdomain(domain):
	print "\n[+] Crawl from Google..."
	global online_subdmn

	# Define number of results
	stuff_that_needs_getting = []
	for i in range(0,10):
		stuff_that_needs_getting.append(str(i*10))

	# Set a google URL global for the multithread
	global google
	google = 'https://www.google.fr/search?&q=site:*.'+domain+"&start="

	# Use multi threads
	pool = multiprocessing.Pool(processes=2)
	pool_outputs = pool.map(crawl_google_for_subdomain_extract, stuff_that_needs_getting)
	pool.close()
	pool.join()

	# Threads are done, now let parse theirs results
	for google_source in pool_outputs:
		websites = tuple(re.finditer(r'<cite>([^\'" <>]+)<\/cite>', google_source[0]))

		for website in websites:
			clean_url = ""
			
			# Handle result like bla.domain
			if(not "http" in website.group(1)):
				clean_url = "http://" + website.group(1)
				clean_url = '/'.join(clean_url.split('/',3)[:-1])

			# Handle result like http://bla.domain
			else:
				clean_url = '/'.join(website.group(1).split('/',3)[:-1])

			if(not clean_url in online_subdmn):
				online_subdmn.append(clean_url)

	# Sort the result for a clean output :)
	online_subdmn = sorted(online_subdmn)
	for subdmn in online_subdmn:
		print "\033[92mFound - \033[0m" + subdmn


# Start a nmap for every subdomains and store the result
def nmap_subdomains():
	if (nmap):
		global online_subdmn
		print "\n[+] NMAP Subdomains"
		for subdmn in online_subdmn:
			clean_url = subdmn.replace('https://','').replace('http://','')
			print " NMAP for "+clean_url
			os.system('nmap -F '+clean_url+' >> reports/'+subdmn.replace('://','_'))


# Generating a report for every subdomain
def generate_reports():
	global online_subdmn
	print "\n[+] Generating subdomain's report"
	
	if not os.path.exists('reports'):
		os.mkdir('reports', 0755)

	for subdmn in online_subdmn:
		path = "reports/"+subdmn.replace('://','_')
		if not os.path.exists(path):
			os.mknod(path)


# Last function save everything
def enf_of_software():
	# Sort the list for a clean output
	global online_subdmn
	online_subdmn = sorted(online_subdmn)
	print "\n[+] Subdomains founds : ",online_subdmn

	# Save subdomain's list
	with open('subdomains.lst','w+') as f:
		f.write("\n".join(online_subdmn))
	print "\n[+] Exported in subdomain.lst"


	# Start a report for every subdomain
	generate_reports()

	# Launch NMAP if necessary
	nmap_subdomains()

	# Exit the soft
	exit(0)
