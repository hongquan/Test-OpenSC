#!/usr/bin/env python

# Test OpenPGP card driver for OpenSC

from __future__ import print_function
import pexpect
import os.path
import re

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

SCerror = {   # From errors.h
	0: 'SC_SUCCESS',

	-1100: 'SC_ERROR_READER',
	-1101: 'SC_ERROR_NO_READERS_FOUND',
	-1104: 'SC_ERROR_CARD_NOT_PRESENT',
	-1105: 'SC_ERROR_CARD_REMOVED',
	-1106: 'SC_ERROR_CARD_RESET',
	-1107: 'SC_ERROR_TRANSMIT_FAILED',
	-1108: 'SC_ERROR_KEYPAD_TIMEOUT',
	-1109: 'SC_ERROR_KEYPAD_CANCELLED',
	-1110: 'SC_ERROR_KEYPAD_PIN_MISMATCH',
	-1111: 'SC_ERROR_KEYPAD_MSG_TOO_LONG',
	-1112: 'SC_ERROR_EVENT_TIMEOUT',
	-1113: 'SC_ERROR_CARD_UNRESPONSIVE',
	-1114: 'SC_ERROR_READER_DETACHED',
	-1115: 'SC_ERROR_READER_REATTACHED',
	-1116: 'SC_ERROR_READER_LOCKED',

	-1200: 'SC_ERROR_CARD_CMD_FAILED',
	-1201: 'SC_ERROR_FILE_NOT_FOUND',
	-1202: 'SC_ERROR_RECORD_NOT_FOUND',
	-1203: 'SC_ERROR_CLASS_NOT_SUPPORTED',
	-1204: 'SC_ERROR_INS_NOT_SUPPORTED',
	-1205: 'SC_ERROR_INCORRECT_PARAMETERS',
	-1206: 'SC_ERROR_WRONG_LENGTH',
	-1207: 'SC_ERROR_MEMORY_FAILURE',
	-1208: 'SC_ERROR_NO_CARD_SUPPORT',
	-1209: 'SC_ERROR_NOT_ALLOWED',
	-1210: 'SC_ERROR_INVALID_CARD',
	-1211: 'SC_ERROR_SECURITY_STATUS_NOT_SATISFIED',
	-1212: 'SC_ERROR_AUTH_METHOD_BLOCKED',
	-1213: 'SC_ERROR_UNKNOWN_DATA_RECEIVED',
	-1214: 'SC_ERROR_PIN_CODE_INCORRECT',
	-1215: 'SC_ERROR_FILE_ALREADY_EXISTS',
	-1216: 'SC_ERROR_DATA_OBJECT_NOT_FOUND',
	-1217: 'SC_ERROR_NOT_ENOUGH_MEMORY',
	-1218: 'SC_ERROR_CORRUPTED_DATA',
	-1219: 'SC_ERROR_FILE_END_REACHED',

	-1300: 'SC_ERROR_INVALID_ARGUMENTS',
	-1303: 'SC_ERROR_BUFFER_TOO_SMALL',
	-1304: 'SC_ERROR_INVALID_PIN_LENGTH',
	-1305: 'SC_ERROR_INVALID_DATA',

	-1400: 'SC_ERROR_INTERNAL',
	-1401: 'SC_ERROR_INVALID_ASN1_OBJECT',
	-1402: 'SC_ERROR_ASN1_OBJECT_NOT_FOUND',
	-1403: 'SC_ERROR_ASN1_END_OF_CONTENTS',
	-1404: 'SC_ERROR_OUT_OF_MEMORY',
	-1405: 'SC_ERROR_TOO_MANY_OBJECTS',
	-1406: 'SC_ERROR_OBJECT_NOT_VALID',
	-1407: 'SC_ERROR_OBJECT_NOT_FOUND',
	-1408: 'SC_ERROR_NOT_SUPPORTED',
	-1409: 'SC_ERROR_PASSPHRASE_REQUIRED',
	-1411: 'SC_ERROR_DECRYPT_FAILED',
	-1412: 'SC_ERROR_WRONG_PADDING',
	-1413: 'SC_ERROR_WRONG_CARD',
	-1414: 'SC_ERROR_CANNOT_LOAD_MODULE',
	-1415: 'SC_ERROR_OFFSET_TOO_LARGE',
	-1416: 'SC_ERROR_NOT_IMPLEMENTED',

	-1500: 'SC_ERROR_PKCS15INIT',
	-1501: 'SC_ERROR_SYNTAX_ERROR',
	-1502: 'SC_ERROR_INCONSISTENT_PROFILE',
	-1503: 'SC_ERROR_INCOMPATIBLE_KEY',
	-1504: 'SC_ERROR_NO_DEFAULT_KEY',
	-1505: 'SC_ERROR_NON_UNIQUE_ID',
	-1506: 'SC_ERROR_CANNOT_LOAD_KEY',
	-1508: 'SC_ERROR_TEMPLATE_NOT_FOUND',
	-1509: 'SC_ERROR_INVALID_PIN_REFERENCE',
	-1510: 'SC_ERROR_FILE_TOO_SMALL',

	-1600: 'SC_ERROR_SM',
	-1601: 'SC_ERROR_SM_ENCRYPT_FAILED',
	-1602: 'SC_ERROR_SM_INVALID_LEVEL',
	-1603: 'SC_ERROR_SM_NO_SESSION_KEYS',
	-1604: 'SC_ERROR_SM_INVALID_SESSION_KEY',
	-1605: 'SC_ERROR_SM_NOT_INITIALIZED',
	-1606: 'SC_ERROR_SM_AUTHENTICATION_FAILED',
	-1607: 'SC_ERROR_SM_RAND_FAILED',
	-1608: 'SC_ERROR_SM_KEYSET_NOT_FOUND',
	-1609: 'SC_ERROR_SM_IFD_DATA_MISSING'
}

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

rootdir = '3f00'
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
		self.testcases = []
		self.result = []
		# RegEx pattern for pexpect.expect(). We will also get the current directory
		# from this.
		self.prompt_pat = 'OpenSC \[([/0-9A-F]+)\]>'
		print("Starting opensc-explorer")
		self.osc = pexpect.spawn('opensc-explorer')
		try:
			self.osc.expect(self.prompt_pat, 10)
		except pexpect.TIMEOUT:
			print("Opensc-explorer hangs. It seems to be not able to connect to the reader.")

	def _send(self, command, verbose=False):
		if verbose:
			print('>>', command)
		self.osc.sendline(command)
		self.osc.expect(self.prompt_pat)
		lastline = self.osc.before.splitlines()[-1]
		if verbose:
			print('<<', lastline)
		return lastline

	def goto_topdir(self):
		path = self.getcurdir()
		if not isinstance(path, tuple):
			print("Error: Can not get current dir.")
			return
		for i in path:
			self.go_updir()

	def go_updir(self):
		self._send('cd ..')

	def goto_dir(self, name):
		self._send('cd {0}'.format(name))

	def getcurdir(self):
		'''Return absolute path to current dir as tuple.'''
		if not self.osc.match: # The current path has not been stored yet.
			self.go_updir()

		if self.osc.match:
			# Get path from the 'OpenSC [3F00/xxxx]>' prompt,
			# which already stored on self.osc.match
			path = self.osc.match.group(1).lower()
			# We strip out the first element, which is the top dir
			return tuple(path[1:])
			# return (), means we are in top dir
		else:  # The current path has not been stored yet.
			return False

	def verify(self, pintype):
		if pintype == 1 or pintype == 2:
			command = 'verify CHV{0} {1}'.format(pintype, self.user_pin.encode('hex'))
		elif pintype == 3:
			command = 'verify CHV3 {0}'.format(self.admin_pin.encode('hex'))
		else:
			print("Unknown PIN type", pintype)
			return False

		lastline = self._send(command)
		if 'Code correct' in lastline:
			return True
		else:
			print('Wrong password:', lastline)
			return False

	def end(self, force=False):
		print('Quit OpenSC')
		if self.osc.isalive():
			if not force:
				self.osc.sendline('quit')
				self.osc.expect(pexpect.EOF)
			else:
				self.osc.close(True)


class TestWrite(Test):
	''' Class to do test writing'''
	def write(self, tag, data):
		return self._send('do_put {0} {1}'.format(tag, data), True)

	def reread(self, tag):
		# Nested DO cannot be read directly.
		# We will make use of emulated folder hierarchy to read the file.
		# Locate the tag to read.
		path = locate(tag)
		print('Path to the DO', path)
		self.goto_topdir()
		for d in path[:-1]:
			self.goto_dir(d)
		return self._send('cat {0}'.format(tag), True)

	def loadfile(self, filename):
		''' Load test cases in text file and parse them. '''
		print("Load test cases from", filename)
		tc = []
		self.tc_file = filename
		with open(filename) as fl:
			for line in fl:
				line = line.lstrip()
				if not line.startswith('#'):
					tc.append(line.rstrip())
		if tc != []:
			self.parse_testcases(tc)

	def parse_testcases(self, lines):
		self.testcases = [tc for tc in map(self.validate_line, lines) if tc is not None]

	def validate_line(self, line):
		''' Check if line is in right format'''
		paramnum = 4
		segs = line.split(";; ")
		if len(segs) != paramnum:
			print('Syntax error: There should be {0} params in line: {1}'.format(paramnum, line))
			return None

		idt, tag, value, expected = map(str.strip, segs)

		if (value.startswith('"') and not value.endswith('"')) \
		   or (value.endswith('"') and not value.startswith('"')):
			print('Syntax error: Wrong value format at line:', l)
			return None

		return (idt, tag.lower(), value, expected)

	def runtestcase(self, tc):
		print("=============")
		print('Run test', tc)
		idt, tag, value, expected = tc
		self.write(tag, value)
		res = self.parse_write_result()
		if res != expected:
			self.set_test_result(tc, 'FAIL')
			return
		if expected != 'SC_SUCCESS':
			# Error test, no need to reread.
			self.set_test_result(tc, 'PASS')
			return
		# Nominal test, reread to guarantee right write
		self.reread(tag)
		# Get the result
		reread = self.parse_reread_result()
		if value.startswith('"'):
			value = value[1:-1].encode('hex')
		print('Write: ', value.upper())
		print('Reread:', reread)
		if value.lower() == reread.lower():
			self.set_test_result(tc, 'PASS')
			return
		else:
			self.set_test_result(tc, 'FAIL')
			return
		self.result.append(', '.join((idt, tag, value, expected, ret)))
		return ret

	def set_test_result(self, tc, ret):
		print('-->', ret)
		t = list(tc)
		t.append(ret)
		self.result.append(', '.join(t))

	def parse_write_result(self):
		lastline = self.osc.before.splitlines()[-1]
		se = re.search('[0-9]+ bytes written', lastline)
		if se:
			return 'SC_SUCCESS'
		se = re.search('Cannot put data .* return (-?[0-9]+)', lastline)
		if se:
			return SCerror[int(se.group(1))]
		se = re.search('unable to parse data', lastline)
		if se:
			return 'SC_ERROR_INVALID_ARGUMENTS'
		return None

	def parse_reread_result(self):
		# Get the result lines in reverse order
		lastlines = self.osc.before.splitlines()[::-1]
		hexstrings = []
		for line in lastlines:
			se = re.search('[0-9]+: ([ 0-9A-F]+) .+', line)
			if not se:
				break
			hexstrings.append(se.group(1))
		hexstrings.reverse()
		return ''.join(hexstrings).replace(' ', '')

	def iteratetest(self):
		self.result = []
		map(self.runtestcase, self.testcases)

		# Write result to file
		if self.tc_file:
			n, e = os.path.splitext(self.tc_file)
			filename = n + '_result' + e
		else:
			filename = 'testresult.txt'
		with open(filename, 'w') as fl:
			fl.write('\n'.join(self.result))