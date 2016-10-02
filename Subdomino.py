#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
import argparse
from subdomain_enum import *

author  = "Swissky"
version = "0.1"

if __name__ == "__main__":
	# Parsing arguments
	parser = argparse.ArgumentParser()
	parser.add_argument('--domain', action ='store',      dest='domain', help="Target domain")
	parser.add_argument('--nmap',   action ='store_true', dest='nmap',   help="Boolean Nmap", default=False)
	results = parser.parse_args()
	
	# Need a domain to start enumerating
	if results.domain == None:
		parser.print_help()
		exit()

	# Banner and version
	print "Subdomino - v" + version + ", by " + author


	# Start a subdomain enumeration
	init_enumeration(results.nmap)
	crawl_google_for_subdomain(results.domain)
	brute_with_file(results.domain)

	# Save everything and end the script
	end_of_software()