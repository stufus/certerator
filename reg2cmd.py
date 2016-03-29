#/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  Certerator 0.1-pre1
#  Stuart Morgan <stuart.morgan@mwrinfosecurity.com> @ukstufus
#
#  This tool will parse a Windows Registry Editor 'reg' file of a certificate,
#  and produce a command line representation of it.
#

import os
import sys
import re

if __name__ == "__main__":
    try:
        # Read the .reg file from STDIN
        regfile = sys.stdin.readlines()
    
        for line in regfile:
            
