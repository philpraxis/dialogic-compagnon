#!/usr/bin/env python
# encoding: utf-8
"""
diadecode.py

Created by Philippe Langlois on 2009-11-11.
Copyright (c) 2009 P1 Security. All rights reserved.

Issues / TODO / Questions:

* Currently, the IS41 PDF is password protected and I canot copy/paste from it. :(
   There will be no support for IS41 messages decoding ;-)
   
* Will Dialogic like this project?

* I guess i'd better put this as an online service because Dialogic could be a pain for using their PDF as DB

* Will SS7 developpers use this project?
"""

import sys
import getopt
import glob
import string

help_message = '''
The help message goes here.
'''


class Usage(Exception):
	def __init__(self, msg):
		self.msg = msg

class message_definition(object):
   """docstring for message_definition"""
   def __init__(self, msg_type):
      super(message_definition, self).__init__()
      self.msg_type = msg_type
      self.db = ""
      self.db_content = ""
      self.definition_start_index = -1
      self.offset_size_index = -1

   def decompose(self, param):
      """docstring for decompose"""
      print "decompose(%s)" % param
      ahead_index = self.offset_size_index + 1
      while self.db_content[ahead_index].strip(string.whitespace + string.punctuation) != "Description":
         #print "Offset + description: %s" % self.db_content[ahead_index].strip()
         x = self.db_content[ahead_index].strip().split(' ')
         p_offset = int(x[0]) * 2
         p_size = int(x[1]) * 2
         text = ' '.join(x[2:])
         while not self.db_content[ahead_index+1].strip().split(' ')[0].isdigit() and self.db_content[ahead_index+1].strip(string.whitespace + string.punctuation) != "Description":
            text = "%s %s" % (text, self.db_content[ahead_index+1].strip())
            ahead_index += 1
         print " %s= 0x%s\t(%s)" % ( x[2], param[p_offset : p_offset + p_size ], text)
         ahead_index += 1


class db(object):
   """Class that stores the Definition DB of Dialogic documents.
   The Definition DB are cut and paste directly from the PDF into XXX.db file.
   XXX is the name of the protocol being described, and the title of the Dialogic documentself."""
   def __init__(self):
      self.debug = True
      super(db, self).__init__()
      self.list = glob.glob("*.db")
      self.contents = {}
   
   def find_definition(self, msg_type):
      """docstring for find_definition"""
      for db in self.list:
         #if self.debug: print db
         content = open(db).readlines()

         self.contents[db] = content            # Cache the read content so that we can accelerate access later

         for index,line in enumerate(content):
            # print line
            if "(0x%s)"%msg_type in line:
               # print line
               if line.split(' ')[0] == "type":
                  print "Found definition: %s in %s" % (line, db)
                  # if  "FIELD NAME MEANING" in content[index-1]:
                  #    print "This is a name-list definition"
                  # else:
                  #    print "This is possible a position definition: %s" % content[index-1]

                  # XXX fill msg_def
                  msg_def = message_definition(msg_type)
                  msg_def.db = db
                  msg_def.db_content = content
                  msg_def.definition_start_index = index
                  
                  ahead_index = index
                  while "Parameter Area".lower() not in content[ahead_index].lower():
                     print "Field description: %s" % content[ahead_index].strip()
                     ahead_index += 1
                  # while "Description" not in content[ahead_index]
                  if "Offset Size Name".lower() in content[ahead_index+1].lower():
                     ahead_index += 1
                     msg_def.offset_size_index = ahead_index
                     return msg_def
                  else:
                     return False


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
         
   def dump_elements(self):
      """docstring for dump_elements"""
      for k, v in self.elements.iteritems():
         print "       %s: %s" % (k, v)
      
         
   # def db_list(self):
   #    """docstring for db_list"""
   #    self.db = glob.glob("*.db")
   
   # def db_find_msg(self, msg_type = False):
   #    """docstring for db_find_msg"""
   #    if msg_type == False:
   #       msg_type = self.elements['t']
   # 
   #    for db in self.db.list:
   #       if self.debug: print db
   #       content = open(db).readlines()
   #       for index,line in enumerate(content):
   #          # print line
   #          if "(0x%s)"%msg_type in line:
   #             print line
   #             if line.split(' ')[0] == "type":
   #                print "Found definition: %s in %s" % (line, db)
   #                if  "FIELD NAME MEANING" in content[index-1]:
   #                   print "This is a name-list definition"
   #                else:
   #                   print "This is possible a position definition: %s" % content[index-1]
   #                return

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

   # print "Payload:" + message
   # msg.db_find_msg()
	msg_def = msg.db.find_definition(msg.elements['t'])
	msg.dump_elements()
	if msg_def != False:
	   msg_def.decompose(msg.elements['p'])

if __name__ == "__main__":
	sys.exit(main())
