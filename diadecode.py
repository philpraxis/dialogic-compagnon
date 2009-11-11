#!/usr/bin/env python
# encoding: utf-8
"""
diadecode.py

Created by Philippe Langlois on 2009-11-11.
Copyright (c) 2009 P1 Security. All rights reserved.
"""

import sys
import getopt
import glob


help_message = '''
The help message goes here.
'''


class Usage(Exception):
	def __init__(self, msg):
		self.msg = msg

class Message(object):
   """Process Messages from Dialogic stack"""
   def __init__(self, message, arg_debug=True):
      super(Message, self).__init__()
      if arg_debug == True:
         self.debug = True
      else:
         self.debug = False
      if self.debug: print "class Message(object): %s" % message
      self.message = message
      parts = self.message.split('-')
      self.msg_type = parts.pop(0)
      if self.debug: print "self.msg_type=%s" % self.msg_type
      if self.debug: print "parts=%s" % parts
      self.elements = {}
      for part in parts:
         element_key = part[0:1]
         self.elements[element_key] = part[1:]
         if self.debug: print "%s:%s" % (element_key, part[1:])
         
   def db_list(self):
      """docstring for db_list"""
      self.db = glob.glob(’*.db’)
   
   def db_find_msg(self, message):
      """docstring for db_find_msg"""
      pass
   
   

def main(argv=None):
	if argv is None:
		argv = sys.argv
	try:
		try:
			opts, args = getopt.getopt(argv[1:], "m:ho:v", ["message=", "help", "output="])
		except getopt.error, msg:
			raise Usage(msg)
	
		# option processing
		for option, value in opts:
			if option == "-v":
				verbose = True
			if option in ("-h", "--help"):
				raise Usage(help_message)
			if option in ("-o", "--output"):
				output = value
			if option in ("-m", "--message"):
				message = value
				msg = Message(message)

	except Usage, err:
		print >> sys.stderr, sys.argv[0].split("/")[-1] + ": " + str(err.msg)
		print >> sys.stderr, "\t for help use --help"
		return 2

	# Do stuff here?
	print "Payload:" + message

if __name__ == "__main__":
	sys.exit(main())
