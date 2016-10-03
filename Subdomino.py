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
	parser.add_argument('--domain', action ='store',      dest='domain', help="Target domain")
	parser.add_argument('--nmap',   action ='store_true', dest='nmap',   help="Boolean Nmap",   default=False)
	parser.add_argument('--google', action ='store_true', dest='google', help="Boolean Google", default=False)
	results = parser.parse_args()
	
	# Need a domain to start enumerating
	if results.domain == None:
		parser.print_help()
		exit(-1)


	# DEBUG
	test = ['https://forum.zenk-security.com','http://www.domxss.com/domxss/01_Basics/06_jquery_old_html.html?1957630659', 'https://m.uber.com']
	interpreter = Interpreter(test)
	interpreter.launch_scans()
	exit()
	#/DEBUG

	# Start a subdomain enumeration
	init_enumeration(results.nmap)

	# Option Google
	crawl_google_for_subdomain(results.google,results.domain) 
	
	# Basic Function
	brute_with_file(results.domain)

	# Save everything and end the script
	end_of_software()