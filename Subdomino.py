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
	parser.add_argument('--domain',     action ='store',      dest='domain',     help="Target domain")
	parser.add_argument('--nmap',       action ='store_true', dest='nmap',       help="Boolean Nmap",        default=False)
	parser.add_argument('--all',        action ='store_true', dest='all',        help="Boolean All Web",     default=False)
	parser.add_argument('--google',     action ='store',      dest='google',     help="N° of Google page",   default=False)
	parser.add_argument('--yahoo',      action ='store',      dest='yahoo',      help="N° of Yahoo page",    default=False)
	parser.add_argument('--baidu',      action ='store',      dest='baidu',      help="N° of Baidu page",    default=False)
	parser.add_argument('--bing',       action ='store',      dest='bing',       help="N° of Bing page",     default=False)
	parser.add_argument('--reversedns', action ='store_true', dest='reversedns', help="Reverse DNS",         default=False)
	parser.add_argument('--names',      action ='store',      dest='names',      help="Names files",         default="names.txt")
	parser.add_argument('--threads',    action ='store',      dest='threads',    help="Number of thread",    default=20)
	results = parser.parse_args()

	# Need a domain to start enumerating
	if results.domain == None:
		parser.print_help()
		exit(-1)

	# Handle crawling with every websites (yahoo, google, bing...)
	if results.all != False:
		results.google     = 10
		results.yahoo      = 10
		results.baidu      = 10
		results.bing       = 10
		results.reversedns = True

	# Start a subdomain enumeration
	init_enumeration(results.nmap)

	# Reverse DNS Search
	reverse_dns_search(results.reversedns, results.domain)

	# Scan on Google and cie
	website_name   = ['Google', 'Yahoo', 'Bing', 'Baidu']
	website_option = [results.google, results.yahoo, results.bing, results.baidu]
	website_regex  = [r'<cite.*?>([^\'" <>]+)<\/cite>',r'href="(.*?'+results.domain+'.*?)" referrerpolicy="origin"',r'<li class="b_algo"><h2><a href="(.*?)"', r'<a.*?class="c-showurl".*?>(.*?)</a>']
	website_url    = ['https://www.google.co.th/search?q=site:*.{} -www.{}&start=','https://search.yahoo.com/search?p=site%3A{}+-www.{}&b=', 'https://www.bing.com/search?q=site%3a{}+-www.{}&first=', 'http://www.baidu.com/s?wd=site%3A{}%20-www.{}&pn=']

	for opt_dork in zip(website_name, website_option, website_url, website_regex):
		crawl_website_for_subdomain(opt_dork[0],int(opt_dork[1]), results.domain, int(results.threads), opt_dork[2], opt_dork[3])
	
	# Basic Function
	brute_with_file(results.names, results.domain, int(results.threads))

	# Save everything and end the script
	end_of_software()