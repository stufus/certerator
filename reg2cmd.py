#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  Certerator 0.1-pre1
#  Stuart Morgan <stuart.morgan@mwrinfosecurity.com> @ukstufus
#
#  https://github.com/stufus/certerator
#
#  This tool will parse a Windows Registry Editor 'reg' file of a certificate,
#  and produce a command line representation of it. It assumes that only one
#  certificate (i.e. one branch) is exported in the reg file.
#
#  It reads the reg file from STDIN. For example:
#     cat export.reg | ./reg2cmd.py
#     ./reg2cmd.py < export.reg
#

import os
import sys
import re

# Read the .reg file from STDIN
regfile = sys.stdin.readlines()
   
reg_base = ""
reg_base_ps = ""
reg_path = ""
reg_key = ""
reg_binary = ""

# Loop through each line
for line in regfile:

    # Try to match the location
    header = re.search(r'^\[([^\\]+)\\(SOFTWARE\\Microsoft\\SystemCertificates\\[^\\]+\\Certificates)\\([A-Z0-9]+)\]\s*$', line, re.IGNORECASE)
    if header != None:
        reg_base = header.group(1)
        reg_path = header.group(2)
        reg_key = header.group(3)

    # Now match the rest of the file
    body = re.search(r'^\s*(?:"Blob"=hex:)?\s*([a-z0-9,]+)[,\\]*\s*$', line)
    if body != None:
        reg_binary += body.group(1).replace(',','')

if reg_base and reg_path and reg_key and reg_binary:
    print "Command line reg.exe:"
    print "reg add %s\\%s\\%s /v Blob /t REG_BINARY /d %s /f /reg:64" % (reg_base, reg_path, reg_key, reg_binary)
    print "\n"
