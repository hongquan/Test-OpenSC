#!/usr/bin/env python

import pexpect

ACCESS_READ_NEVER   = 0
ACCESS_READ_PIN3    = 1
ACCESS_READ_PIN2    = 2
ACCESS_READ_PIN1    = 3
ACCESS_READ_ALWAYS  = 4

ACCESS_WRITE_NEVER   = 0
ACCESS_WRITE_PIN3    = 1
ACCESS_WRITE_PIN2    = 2
ACCESS_WRITE_PIN1    = 3
ACCESS_WRITE_ALWAYS  = 4

DOaccess = {   # From card-openpgp.c
	'004d': (ACCESS_READ_NEVER, ACCESS_WRITE_PIN3),
	'004f': (ACCESS_READ_ALWAYS, ACCESS_WRITE_NEVER),
	'005b': (ACCESS_READ_ALWAYS, ACCESS_WRITE_PIN3),
	'005e': (ACCESS_READ_ALWAYS, ACCESS_WRITE_PIN3),
	'0065': (ACCESS_READ_ALWAYS, ACCESS_WRITE_NEVER),
	'006e': (ACCESS_READ_ALWAYS, ACCESS_WRITE_NEVER),
	'0073': (ACCESS_READ_ALWAYS, ACCESS_WRITE_NEVER),
	'007a': (ACCESS_READ_ALWAYS, ACCESS_WRITE_NEVER),
	'0081': (ACCESS_READ_ALWAYS, ACCESS_WRITE_NEVER),
	'0082': (ACCESS_READ_ALWAYS, ACCESS_WRITE_NEVER),
	'0093': (ACCESS_READ_ALWAYS, ACCESS_WRITE_NEVER),
	'00c0': (ACCESS_READ_ALWAYS, ACCESS_WRITE_NEVER),
	'00c1': (ACCESS_READ_ALWAYS, ACCESS_WRITE_PIN3),
	'00c2': (ACCESS_READ_ALWAYS, ACCESS_WRITE_PIN3),
	'00c3': (ACCESS_READ_ALWAYS, ACCESS_WRITE_PIN3),
	'00c4': (ACCESS_READ_ALWAYS, ACCESS_WRITE_PIN3),
	'00c5': (ACCESS_READ_ALWAYS, ACCESS_WRITE_PIN3),
	'00c6': (ACCESS_READ_ALWAYS, ACCESS_WRITE_PIN3),
	'00c7': (ACCESS_READ_NEVER, ACCESS_WRITE_PIN3),
	'00c8': (ACCESS_READ_NEVER, ACCESS_WRITE_PIN3),
	'00c9': (ACCESS_READ_NEVER, ACCESS_WRITE_PIN3),
	'00ca': (ACCESS_READ_NEVER, ACCESS_WRITE_PIN3),
	'00cb': (ACCESS_READ_NEVER, ACCESS_WRITE_PIN3),
	'00cc': (ACCESS_READ_NEVER, ACCESS_WRITE_PIN3),
	'00cd': (ACCESS_READ_ALWAYS, ACCESS_WRITE_PIN3),
	'00ce': (ACCESS_READ_NEVER, ACCESS_WRITE_PIN3),
	'00cf': (ACCESS_READ_NEVER, ACCESS_WRITE_PIN3),
	'00d0': (ACCESS_READ_NEVER, ACCESS_WRITE_PIN3),
	'00d1': (ACCESS_READ_NEVER, ACCESS_WRITE_PIN3),
	'00d2': (ACCESS_READ_NEVER, ACCESS_WRITE_PIN3),
	'00d3': (ACCESS_READ_NEVER, ACCESS_WRITE_PIN3),
	'00f4': (ACCESS_READ_NEVER, ACCESS_WRITE_PIN3),
	'0101': (ACCESS_READ_ALWAYS, ACCESS_WRITE_PIN3),
	'0102': (ACCESS_READ_ALWAYS, ACCESS_WRITE_PIN3),
	'0103': (ACCESS_READ_PIN1, ACCESS_WRITE_PIN1),
	'0104': (ACCESS_READ_PIN3, ACCESS_WRITE_PIN3),
	'3f00': (ACCESS_READ_ALWAYS, ACCESS_WRITE_NEVER),
	'5f2d': (ACCESS_READ_ALWAYS, ACCESS_WRITE_PIN3),
	'5f35': (ACCESS_READ_ALWAYS, ACCESS_WRITE_PIN3),
	'5f48': (ACCESS_READ_NEVER, ACCESS_WRITE_PIN3),
	'5f50': (ACCESS_READ_ALWAYS, ACCESS_WRITE_PIN3),
	'5f52': (ACCESS_READ_ALWAYS, ACCESS_WRITE_NEVER),
	'7f21': (ACCESS_READ_ALWAYS, ACCESS_WRITE_PIN3),
	'7f48': (ACCESS_READ_NEVER, ACCESS_WRITE_NEVER),
	'7f49': (ACCESS_READ_ALWAYS, ACCESS_WRITE_NEVER),
	'a400': (ACCESS_READ_ALWAYS, ACCESS_WRITE_NEVER),
	'a401': (ACCESS_READ_ALWAYS, ACCESS_WRITE_NEVER),
	'b600': (ACCESS_READ_ALWAYS, ACCESS_WRITE_NEVER),
	'b601': (ACCESS_READ_ALWAYS, ACCESS_WRITE_NEVER),
	'b800': (ACCESS_READ_ALWAYS, ACCESS_WRITE_NEVER),
	'b801': (ACCESS_READ_ALWAYS, ACCESS_WRITE_NEVER)
}

DOtree = {
	'0101': None,  # 'None' means this DO is simple.
	'0102': None,
	'0103': None,
	'0104': None,
	'004f': None,
	'005e': None,
	'5f50': None,
	'5f52': None,

	'0065': {      # 'dict' means this DO is constructed.
		'005b': None,
		'5f2d': None,
		'5f35': None
	},

	'006e': {
		'004f': None,
		'5f52': None,
		'0073': {
			'00c0': None,
			'00c1': None,
			'00c2': None,
			'00c3': None,
			'00c4': None,
			'00c5': None,
			'00c6': None,
			'00cd': None,
		}
	},

	'007a': {
		'0093': None
	},

	'7f21': {},   # This DO is special: Contructed but has no simple DO under it.

	'00c4': None
}

_cached_path = {}     # Cache the location of DOs to avoid cost of repeated searching

def locate(tag):
	''' Locate the DO in the tree. Return absolute path as tuple. '''
	try:
		# Get from cache
		return _cached_path[tag]
	except KeyError:
		# Not cached yet
		path = search_in_tree(DOtree, tag)
		if path:
			# The last result is in reversed order
			path.reverse()
			# No more manipulation on the list, change to tuple to save memory.
			path = tuple(path)
			# Add to cache
			_cached_path[tag] = path
			return path
		else:
			return False

def search_in_tree(root, tag, path=[]):
	''' Recursive function to search for DO tag in tree.
	Return path as reversed list.'''
	if tag in root:
		path.append(tag)
		return path
	for name, branch in root.iteritems():
		if branch != None and branch != {}:
			found = search_in_tree(branch, tag, path)
			if found:
				# Won't update "path" variable because it has been modified
				# inside search_in_tree already.
				found.append(name)
				return found
	return False

class Test:
	''' Base class to test for OpenPGP card with OpenSC'''
	def __init__(self, user_pin=None, admin_pin=None):
		self.user_pin = user_pin
		self.admin_pin = admin_pin
		self.prompt_pat = 'OpenSC \[([/0-9A-F]+)\]>'
		self.osc = pexpect.spawn('opensc-explorer')
		self.osc.expect(self.prompt_pat)

	def _send(self, command):
		print '>>', command
		self.osc.sendline(command)
		self.osc.expect(self.prompt_pat)
		lastline = self.osc.before.splitlines()[-1]
		print '<<', lastline
		return lastline

	def verify(self, pintype):
		if pintype == 1 or pintype == 2:
			command = 'verify CHV%d %s' % (pintype, self.user_pin.encode('hex'))
		elif pintype == 3:
			command = 'verify CHV3 %s' % self.admin_pin.encode('hex')
		else:
			print "Unknown PIN type", pintype
			return False

		lastline = self._send(command)
		if 'Code correct' in lastline:
			return True
		else:
			print 'Wrong password:', lastline
			return False

	def end(self):
		print 'Quit OpenSC'
		self.osc.sendline('quit')


class TestWrite(Test):
	''' Class to do test writing'''
	def writestring(self, tag, data):
		self._send('do_put %s "%s"' % (tag, data))

	def writehex(self, tag, data):
		self._send('do_put %s %s' % (tag, data.encode('hex')))

	def reread(self, tag):
		# Nested DO cannot be read directly.
		# We will make use of emulated folder hierarchy to read the file
		self._send('cat %s' % tag)
