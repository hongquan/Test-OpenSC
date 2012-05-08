#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import pexpect
import osctest

admin_pin = "12345678"
user_pin = "123456"

test = osctest.TestWrite(user_pin, admin_pin)
test.verify(3)
test.writestring('005b', 'Nguyen Hong Quan')
test.end()