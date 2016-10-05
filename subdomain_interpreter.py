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
					self.names.append(l.strip('\n').replace('name: ',''))
				if l[0:6] == "rule: ":
					self.rules.append(l.strip('\n').replace('rule: ',''))

		
	# Save IOV in the subdomains file
	def report_IOV(self, name, subdomain, iov):
		print "\t\033[1mIOV '" + iov + "' found : \033[0m"+ name + " for " + subdomain
		path = "reports/"+subdomain.replace('://','_')
		with open(path, 'a+') as f:
			f.write('IOV '+ iov + ' - ' + name)


	"""	<Start Of Rules> """
	# Rule: is_string_page()
	def rule_is_string_page(self,r,part):
		regex = re.compile('is_string_page\("(.*?)"\)')		
		regex = regex.findall(part)
		if( regex != []):		
			if regex[0] in r.text:		
				return 1
		return 0	

	# Rule: is_string_header()
	def rule_is_string_header(self,r,part):
		regex = re.compile('is_string_header\("(.*?)"\)')			
		regex = regex.findall(part)
		if( regex != []):
			if regex[0] in str(r.headers):
				return 1
		return 0

	# Rule: regex_match_page()
	def rule_regex_match_page(self,r,part):
		regex = re.compile('regex_match_page\("(.*?)"\)')			
		regex = regex.findall(part)
		if( regex != []):
			regex_rule = re.compile(regex[0])
			regex_rule = regex_rule.findall(r.text)
			if (regex_rule != []):
				return 1
		return 0

	# Rule: regex_match_page()
	def rule_regex_match_header(self,r,part):
		regex = re.compile('regex_match_header\("(.*?)"\)')			
		regex = regex.findall(part)
		if( regex != []):
			regex_rule = re.compile(regex[0])
			regex_rule = regex_rule.findall(str(r.headers))
			if (regex_rule != []):
				return 1
		return 0
	
	""" </Enf Of Rules> """


	# Engine which will parse every rules
	"""
	Note: to add a new rule interpretation, you need to :
	- do a function called rule_nameofinterpretation(self,r,part)
	- add the 'if self.rule_nameofinterpretation(r,part):' in the following code
	- add the 'and_result += self.rule_nameofinterpretation(r,part)'
	"""
	def rules_engine(self, r, subdomain):

		# Go thru every rule in ['rule1', 'rule2']	['name1','name2']
		for rule,name in zip(self.rules, self.names):

			# Handling AND Operator
			if "AND" in rule:
				# Strip space and split by AND to have an array of rules
				and_list   = rule.replace(' ','').split('AND')
				and_result = 0

				# Split the rule in several part ['A B C'] -> A,B,C
				for part in and_list:
					and_result += self.rule_is_string_page(r,part)
					and_result += self.rule_is_string_header(r,part)
					and_result += self.rule_regex_match_page(r,part)
					and_result += self.rule_regex_match_header(r,part)

				# Compare the number of rules and the number of matched rule
				if and_result == len(and_list):
					self.report_IOV(name, subdomain, "multiple rules")
			else:

				# Split the rule in several part ['A B C'] -> A,B,C
				for part in rule.split(' '):

					# is_string_page()
					if self.rule_is_string_page(r,part):
						self.report_IOV(name, subdomain, "is_string_page")

					# is_string_header()
					if self.rule_is_string_header(r,part):
						self.report_IOV(name, subdomain, "is_string_header")

					# regex_match_page()
					if self.rule_regex_match_page(r,part):
						self.report_IOV(name, subdomain, "regex_match_page")

					# regex_match_header()
					if self.rule_regex_match_header(r,part):
						self.report_IOV(name, subdomain, "regex_match_header")



	# Start a scan with the rules for every subdomains
	def launch_scans(self):
		print "\n[+] Scan subdomains using the rules Interpreter"
		for subdomain in  self.subdomains:
			try:
				r = requests.get(subdomain)
				self.rules_engine(r, subdomain)
			except Exception, e:
				pass