#!/usr/bin/env python

# Parse a hex string encoded in DER-TLV

from __future__ import print_function

def parse_flat(string):
	''' Extract from hex string to TLV objects.
	The TLVs are in serial, not nested'''
	bstring = bytearray(string.replace(' ', '').decode('hex'))
	i = 0
	tlvlist = {}
	tag, length, value = False, False, False
	while i < len(bstring):
		byte = bstring[i]
		if not isinstance(tag, bytearray): # Tag was not get (False) or incomplete (list)
			# Get tag
			tag = get_tag(byte, tag)
			i += 1
		elif not isinstance(length, bytearray):
			j = get_num_subsequent_lengthbytes(byte, length)
			if j == 0:
				length = bytearray([byte])
			else:
				length = bstring[i+1:i+1+j]
			i = i + 1 + j
		elif not isinstance(value, bytearray):
			le = bytearraytoint(length)
			value = bstring[i:i+le]
			i = i + le
		if isinstance(tag, bytearray) and isinstance(length, bytearray) \
		   and isinstance(value, bytearray):
			# Change the tag from bytearray to '005B' form
			# Is there better way?
			tag = '{0:>04}'.format('{0}'.format(tag).encode('hex'))
			tlvlist[tag] = (le, '{0}'.format(value).encode('hex'))
			tag, length, value = False, False, False
	return tlvlist

def get_tag(byte, tag):
	if tag is False:  # Fist byte of tag
		b = byte & 0b00011111
		if b != 0b00011111:  # single byte tag
			return bytearray([byte])
		# Multi-byte tag
		return [byte]
	else:     # Subsequent bytes
		tag.append(byte)
		# Check if last byte
		b = (byte & 0b10000000)
		if b == 0:
			tag = bytearray(tag) # list to bytearray
		return tag

def get_num_subsequent_lengthbytes(byte, length):
	b = byte & 0b10000000
	if b == 0: # single byte
		return 0
	# Multi byte
	return byte & 0b011111111

def bytearraytoint(barray):
	t = 0
	for n, b in enumerate(barray[::-1]):
		t = t + b*0x100**n
	return t