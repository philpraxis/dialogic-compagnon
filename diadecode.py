#!/usr/bin/env python
# encoding: utf-8
"""
diadecode.py

Created by Philippe Langlois on 2009-11-11.
Copyright (c) 2009 P1 Security. All rights reserved.
http://www.p1security.com/

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
Created by Philippe Langlois on 2009-11-11.
Copyright (c) 2009 P1 Security. All rights reserved.
http://www.p1security.com/

Usage: diadecode.py -m <message>
"-h", "--help":
	this message
"-m", "--message":
   message you want to decode

Example:
./diadecode.py -m M-t7740-i0000-fef-d33-r8000-p018381063322efef00000002011000ef001c000000000000000000000000000000000000000000000000000000000000000000000000000000000000
./diadecode.py -m M-t7780-i0000-fef-d14-r8000-p001415339e9e00000000002000400040000080000410080200ff0000000000000000000000000000

Configuration for s7_play for Dialogic are not really super clear:
**************************************************************
*    SCCP Configuration.
**************************************************************
*       Issue configuration message to the SCCP module:
*                                          --maint_id
*                                    --mod_id                ----SMB flags
*                                ----options --------pc    --SMB id
*                              --sio     --mgmt_id       --SCCP inst
*                            --ver     --mtp_id      ----max_sif -- num_uc
M-t7740-i0000-fef-d33-r8000-p018303223322efef00000002011000ef0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

Logs from Dialogic are typically cryptic:
S7L:I0000 M t32da i0000 fd2 def r0000 s00 e00000000 p0002000000010000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
S7L:I0000 M t02f0 i0000 fd2 def r0000 s00 e00000000 p0000000100020000000000010000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
S7L:I0000 M t02db i0000 fd2 def r0000 s00 e00000000 p00000002
S7L:I0000 M t02e0 i0000 fd2 def r0000 s00 e00000000 p0002
S7L:I0000 M t0762 i7740 f33 def r0000 s05 e000000cd
S7L:I0000 SCCP Software event : SCPSWE_BAD_MSG
S7L:I0000 M t3740 i0000 f33 def r0000 s05 e00000000 p018303223322efef00000001011000ef0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
S7L:I0000 M t3741 i0000 f33 def r0000 s06 e00000000 p00031401000000000800000000000000000000000000000000000000000000000000000000000000
S7L:I0000 M t3741 i0000 f33 def r0000 s06 e00000000 p00010000000000020000000000000000000000000000000000000000000000000000000000000000
S7L:I0000 M t3741 i0000 f33 def r0000 s06 e00000000 p00020000000000020800000000000000000000000000000000000000000000000000000000000000
S7L:I0000 M t8744 i0008 f33 def r0000 s00 e00000000 p0101000000000000
S7L:I0000 M t07a2 i7780 f14 def r0000 s06 e000000cd
S7L:I0000 TCAP Software event : TCPSWE_BAD_MSG
S7L:I0000 M t3780 i0000 f14 def r0000 s05 e00000000 p000015339e9e00000020000000400040000080000410080200ff0000000000000000000000000000
S7L:I0000 M t1795 i0000 f14 def r0000 s00 e00000000 p0000000f0000000f0000007f

The *.db files must be in the current directory where you execute this program.
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
      split_string = ""
      while self.db_content[ahead_index].strip(string.whitespace + string.punctuation) != "Description":
         #print "Offset + description: %s" % self.db_content[ahead_index].strip()
         x = self.db_content[ahead_index].strip().split(' ')
         p_offset = int(x[0]) * 2
         p_size = int(x[1]) * 2
         text = ' '.join(x[2:])
         while not self.db_content[ahead_index+1].strip().split(' ')[0].isdigit() and self.db_content[ahead_index+1].strip(string.whitespace + string.punctuation) != "Description":
            text = "%s %s" % (text, self.db_content[ahead_index+1].strip())
            ahead_index += 1
         split_string = split_string + param[p_offset : p_offset + p_size ] + " "
         print " %s= 0x%s\t(%s)" % ( x[2], param[p_offset : p_offset + p_size ], text)
         ahead_index += 1
      print split_string


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

def main(argv=None):
	message = False
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
		
	if message == False:
	   print help_message
	   return 3

   # print "Payload:" + message
   # msg.db_find_msg()
	msg_def = msg.db.find_definition(msg.elements['t'])
	msg.dump_elements()
	if msg_def != False:
	   msg_def.decompose(msg.elements['p'])

if __name__ == "__main__":
	sys.exit(main())
