#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
import argparse
from subdomain_enum import *

if __name__ == "__main__":
	# Banner and version
	print "\033[1mSubdomino - v0.1, by Swissky\033[0m"

	# Parsing arguments
	parser = argparse.ArgumentParser()
	parser.add_argument('--domain', action ='store',      dest='domain',  help="Target domain")
	parser.add_argument('--nmap',   action ='store_true', dest='nmap',    help="Boolean Nmap",        default=False)
	parser.add_argument('--all',    action ='store_true', dest='all',     help="Boolean All Web",     default=False)
	parser.add_argument('--google', action ='store',      dest='google',  help="N° of Google page",   default=False)
	parser.add_argument('--yahoo',  action ='store',      dest='yahoo',   help="N° of Yahoo page",    default=False)
	parser.add_argument('--bing',   action ='store',      dest='bing',    help="N° of Bing page",     default=False)
	parser.add_argument('--names',  action ='store',      dest='names',   help="Names files",         default="names.txt")
	parser.add_argument('--threads',action ='store',      dest='threads', help="Number of thread",    default=20)
	results = parser.parse_args()

	# Need a domain to start enumerating
	if results.domain == None:
		parser.print_help()
		exit(-1)

	# Handle crawling with every websites (yahoo, google, bing...)
	if results.all != False:
		results.google = 10
		results.yahoo  = 10
		results.bing   = 10

	# Start a subdomain enumeration
	init_enumeration(results.nmap)

	# Option Google
	crawl_google_for_subdomain(int(results.google),results.domain, int(results.threads)) 

	# Option Yahoo
	crawl_yahoo_for_subdomain(int(results.yahoo),results.domain, int(results.threads)) 

	# Option Bing
	crawl_bing_for_subdomain(int(results.bing),results.domain, int(results.threads)) 
	
	# Basic Function
	brute_with_file(results.names, results.domain, int(results.threads))

	# Save everything and end the script
	end_of_software()