#!/usr/bin/python
# -*- coding: utf-8 -*-
import time
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
from multiprocessing import Process, Pool

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

# Multiprocessing ping scan
def multiprocessing_ping_scan(host,n_iter,n_max):
	try:
		if scan_subdomain(host):
			print "n° {:>4}/{} - \033[92mUP - \033[0m{}".format(n_iter, n_max, host)
			return host
		else:
			return None

	except KeyboardInterrupt,e:
		return None

# Generate a list of potential subdomain
def brute_with_file(domain, process):
	print "\n[+] Brute subdomain from names.txt ..."
	global online_subdmn

	# Subdomain extensions are stored in names.txt
	with open('names.txt','r') as dict_file:
		dict_file = dict_file.readlines()
		pool = Pool(process)

		# Multiprocessing
		max_subdmn = len(dict_file)
		for index,subdmn in enumerate(dict_file):
			pool.apply_async(multiprocessing_ping_scan, ("http://"+subdmn.strip()+"."+domain, index, max_subdmn), callback=online_subdmn.append)
    	
    	# We need this to stop it with Ctrl+C
		try:
			time.sleep(10)
			pool.close()
			pool.join()


		except KeyboardInterrupt:
			print " Multiprocessing stopped!"
			pool.terminate()
			pool.join()

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
		os.mkdir('reports',0755)

	# Save subdomain's list
	with open('reports/subdomains.lst','w+') as f:
		f.write("\n".join(online_subdmn))
	print "\n[+] Exported in subdomain.lst"

	# One report for every subdomains - if nmap option enabled
	global nmap
	if nmap == True:
		for subdmn in online_subdmn:
			path = "reports/"+subdmn.replace('://','_')
			if not os.path.exists(path):
				open(path,'w+')

# Last function save everything
def end_of_software():
	
	# Sort the list for a clean output
	global online_subdmn
	online_subdmn = filter(None, online_subdmn)
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