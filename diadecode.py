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

class db(object):
   """Class that stores the Definition DB of Dialogic documents.
   The Definition DB are cut and paste directly from the PDF into XXX.db file.
   XXX is the name of the protocol being described, and the title of the Dialogic documentself."""
   def __init__(self):
      self.debug = True
      super(db, self).__init__()
      self.list = glob.glob("*.db")
      self.contents = {}
      
   def find_msg(self, msg_type):
      """docstring for db_find_msg"""
      for db in self.list:
         if self.debug: print db
         content = open(db).readlines()

         self.contents[db] = content            # Cache the read content so that we can accelerate access later

         for index,line in enumerate(content):
            # print line
            if "(0x%s)"%msg_type in line:
               print line
               if line.split(' ')[0] == "type":
                  print "Found definition: %s in %s" % (line, db)
                  if  "FIELD NAME MEANING" in content[index-1]:
                     print "This is a name-list definition"
                  else:
                     print "This is possible a position definition: %s" % content[index-1]
                  return


class Message(object):
   """Process Messages from Dialogic stack"""
   def __init__(self, message, arg_debug=False):
      super(Message, self).__init__()
      if arg_debug == True:
         self.debug = True
      else:
         self.debug = False
      if self.debug: print "class Message(object): %s" % message

      # self.db_list()
      self.db = db()

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
         
   # def db_list(self):
   #    """docstring for db_list"""
   #    self.db = glob.glob("*.db")
   
   def db_find_msg(self, msg_type = False):
      """docstring for db_find_msg"""
      if msg_type == False:
         msg_type = self.elements['t']

      for db in self.db.list:
         if self.debug: print db
         content = open(db).readlines()
         for index,line in enumerate(content):
            # print line
            if "(0x%s)"%msg_type in line:
               print line
               if line.split(' ')[0] == "type":
                  print "Found definition: %s in %s" % (line, db)
                  if  "FIELD NAME MEANING" in content[index-1]:
                     print "This is a name-list definition"
                  else:
                     print "This is possible a position definition: %s" % content[index-1]
                  return

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
	msg.db_find_msg()
	print "NEW>>>>>"
	msg.db.find_msg(msg.elements['t'])

if __name__ == "__main__":
	sys.exit(main())
