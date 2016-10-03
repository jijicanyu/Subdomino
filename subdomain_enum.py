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
from subdomain_scan import *
from subdomain_interpreter import *

# Initialize the global variable
def init_enumeration(is_nmap):
	# Storing all the subdomains
	global online_subdmn
	online_subdmn = []

	# Handle nmap scan for every subdomain 
	# Using global variable because of the signal handler
	global nmap
	if (is_nmap):
		print "[OPTION] Nmap Scan enabled"
	else:
		print "[OPTION] Nmap Scan disabled"
	nmap = is_nmap

# CTRL+C Handler
def signal_handler(signal, frame):
	enf_of_software()

# Generate a list of potential subdomain
def brute_with_file(domain):
	print "\n[+] Brute subdomain from names.txt ..."
	# This interruption will manage CTRL+C in different states
	signal.signal(signal.SIGINT, signal_handler)

	with open('names.txt','r') as dict_file:
		dict_file = dict_file.readlines()
		
		# Determine online subdomain
		for subdmn in (dict_file):
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
def crawl_google_for_subdomain(is_google,domain):
	if (is_google):
		print "[OPTION] Google Scan enabled"
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
	else:
		print "[OPTION] Google Scan disabled"

# Generating a report for every subdomain
def generate_reports():
	global online_subdmn
	print "\n[+] Generating subdomain's report"

	# Create the directory
	if not os.path.exists('reports'):
		os.makedirs('reports')

	# Save subdomain's list
	with open('reports/subdomains.lst','w+') as f:
		f.write("\n".join(online_subdmn))
	print "\n[+] Exported in subdomain.lst"

	# One report for every subdomains
	for subdmn in online_subdmn:
		path = "reports/"+subdmn.replace('://','_')
		if not os.path.exists(path):
			open(path,'w+')

# Last function save everything
def enf_of_software():
	# Sort the list for a clean output
	global online_subdmn
	online_subdmn = sorted(online_subdmn)
	print "\n[+] Subdomains founds : ",online_subdmn

	# Start a report for every subdomain
	generate_reports()

	# Launch NMAP if necessary
	nmap_subdomains(online_subdmn, nmap)

	# Rule Interpreter
	interpreter = Interpreter(online_subdmn)
	interpreter.launch_scans()

	# Exit the soft
	exit(0)