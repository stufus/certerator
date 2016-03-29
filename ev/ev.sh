#!/bin/sh
openssl req -new -config ev_openssl.cnf -out ev.csr -newkey rsa:2048 -keyout ev.key -nodes
openssl ca -in ev.csr -out ev.pem -config ./ev_openssl.cnf
