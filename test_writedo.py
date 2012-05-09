#!/usr/bin/env python
# -*- encoding: utf-8 -*-

# Test OpenPGP card driver for OpenSC

import pexpect
import osctest

admin_pin = "12345678"
user_pin = "123456"

test = osctest.TestWrite(user_pin, admin_pin)
test.verify(3)
test.loadfile('testcases.txt')
test.iteratetest()
test.end()