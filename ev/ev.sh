#!/bin/sh
# Certerator
# (C) Stuart Morgan <stuart.morgan@mwrinfosecurity.com> @ukstufus
#
# https://github.com/stufus/certerator
#
# This is a basic shell script which, in combination with ev_openssl.cnf, will create
# a certificate with an OID in the 'certificatePolicies' attribute. If this OID is
# associated with the signing certification authority and marked as an EV CA, it will
# effectively masquerade as an EV certificate.
#
openssl req -new -config ev_openssl.cnf -out ev.csr -newkey rsa:2048 -keyout ev.key -nodes
openssl ca -in ev.csr -out ev.pem -config ./ev_openssl.cnf
