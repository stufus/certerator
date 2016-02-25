#/usr/bin/env python
import os
import sys
import OpenSSL

def certerator_config():
    ca = {}
    cert = {}

    ca['commonName'] = "MWR Root Authority"
    ca['stateOrProvinceName'] = "Hampshire"
    ca['localityName'] = "Basingstoke"
    ca['organizationName'] = "MWR InfoSecurity"
    ca['organizationalUnitName'] = "Certification Authority"
    ca['emailAddress'] = "labs@mwrinfosecurity.com"
    ca['countryName'] = "GB"
    ca['cert_filename'] = "ca.pem"
    ca['cert_key'] = "ca.key"
    ca['serial'] = 123456
    ca['validfrom'] = "20100101000000Z"
    ca['validto'] = "20200101000000Z"
    ca['keyfilesize'] = 4096
    ca['hashalgorithm'] = "sha256"

    cert['commonName'] = "MWR Code Signing Verifier"
    cert['stateOrProvinceName'] = "Hampshire"
    cert['localityName'] = "Basingstoke"
    cert['organizationName'] = "MWR InfoSecurity"
    cert['organizationalUnitName'] = "Code Management"
    cert['emailAddress'] = "labs@mwrinfosecurity.com"
    cert['countryName'] = "GB"
    cert['cert_filename'] = "ca.pem"
    cert['cert_key'] = "ca.key"
    cert['serial'] = 234567
    cert['validfrom'] = "20150101000000Z"
    cert['validto'] = "20180101000000Z"
    cert['keyfilesize'] = 4096

    return ca, cert

def openssl_generate_privatekey(size):
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, size)
    return key

def generate_certificate(config_ca,key):
    ca = OpenSSL.crypto.X509()
    ca.set_version(2)
    ca.set_serial_number(config_ca['serial'])
    ca_subj = ca.get_subject()
    ca_subj.commonName = config_ca['commonName']
    ca_subj.stateOrProvinceName = config_ca['stateOrProvinceName']
    ca_subj.localityName = config_ca['localityName']
    ca_subj.organizationName = config_ca['organizationName']
    ca_subj.organizationalUnitName = config_ca['organizationalUnitName']
    ca_subj.emailAddress = config_ca['emailAddress']
    ca_subj.countryName = config_ca['countryName']
    ca.set_notBefore(config_ca['validfrom'])
    ca.set_notAfter(config_ca['validto'])
    return ca

def generate_ca(config_ca):
    key = openssl_generate_privatekey(config_ca['keyfilesize'])
    ca = generate_certificate(config_ca,key)
    ca.add_extensions([
        OpenSSL.crypto.X509Extension("basicConstraints", True,
                               "CA:TRUE, pathlen:1"),
        OpenSSL.crypto.X509Extension("keyUsage", True,
                               "keyCertSign, cRLSign"),
        OpenSSL.crypto.X509Extension("subjectKeyIdentifier", False, "hash",
                               subject=ca),
    ])
    ca.add_extensions([
        OpenSSL.crypto.X509Extension("authorityKeyIdentifier", False, "keyid:always",issuer=ca)
    ])
    ca.set_issuer(ca.get_subject())
    ca.set_pubkey(key)
    ca.sign(key, config_ca['hashalgorithm'])
    return ca, key

if __name__ == "__main__":
    sys.stdout.write("Certerator v0.1-pre1")
    sys.stdout.write("Stuart Morgan (@ukstufus) <stuart.morgan@mwrinfosecurity.com>")
    sys.stdout.flush()

    config_ca, config_cert = certerator_config()
    ca, key = generate_ca(config_ca)

    open(config_ca['cert_filename'], "wb").write(
                OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, ca))
    open(config_ca['cert_key'], "wb").write(
                OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))
    sys.exit(0)

