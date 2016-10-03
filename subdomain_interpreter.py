#!/usr/bin/python
# -*- coding: utf-8 -*-
import re
import os
import sys
import requests

class Interpreter():
	rules      = []
	names      = []
	subdomains = []


	def __init__(self, subdomains):
		# Store subdomains for the scan
		self.subdomains = subdomains

		# Parse rules from file 'rules.txt'
		with open('rules.txt','r') as f:
			lines = f.readlines()
			for l in lines:
				if l[0:6] == "name: ":
					self.names.append(l.strip('\n').strip('name: '))
				if l[0:6] == "rule: ":
					self.rules.append(l.strip('\n').strip('rule: '))

		

	# Engine which will parse every rules
	def rule_engine(self, r, subdomain):

		# Go thru every rule in ['rule1', 'rule2']	['name1','name2']
		for rule,name in zip(self.rules, self.names):

			# Split the rule in several part ['A B C'] -> A,B,C
			for part in rule.split(' '):

				# is_string_page()
				regex = re.compile('is_string_page\("(.*?)"\)')		
				regex = regex.findall(part)
				if( regex != []):		
					if regex[0] in r.text:			
						print "IOV 'is_string_page' found : "+ name + " for " + subdomain

				# is_string_header()
				regex = re.compile('is_string_header\("(.*?)"\)')			
				regex = regex.findall(part)
				if( regex != []):
					if regex[0] in str(r.headers):
						print "IOV 'is_string_header' found : "+ name + " for " + subdomain

				# regex_match_page()
				regex = re.compile('regex_match_page\("(.*?)"\)')			
				regex = regex.findall(part)
				if( regex != []):
					regex_rule = re.compile(regex[0])
					regex_rule = regex_rule.findall(r.text)
					if (regex_rule != []):
						print "IOV 'regex_match_page' found : "+ name + " for " + subdomain

				# regex_match_header()
				regex = re.compile('regex_match_header\("(.*?)"\)')			
				regex = regex.findall(part)
				if( regex != []):
					regex_rule = re.compile(regex[0])
					regex_rule = regex_rule.findall(str(r.headers))
					if (regex_rule != []):
						print "IOV 'regex_match_header' found : "+ name + " for " + subdomain

				


	# Start a scan with the rules for every subdomains
	def launch_scans(self):
		for subdomain in  self.subdomains:
			r = requests.get(subdomain)
			self.rule_engine(r, subdomain)