#!/usr/bin/python
# -*- coding: utf-8 -*-
import re
import os
import sys

class Interpreter():
	rules      = []
	subdomains = []

	def __init__(self, subdomains):
		self.subdomains = subdomains
		# Open rules.txt TODO
		
	def launch_scans(self):
		print self.subdomains
