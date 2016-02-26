#/usr/bin/env python
# -*- coding: utf-8 -*-
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

def generate_cert(config_cert, config_ca):
    key = openssl_generate_privatekey(config_cert['keyfilesize'])
    ca = generate_certificate(config_cert,key)
    ca.add_extensions([
        OpenSSL.crypto.X509Extension("basicConstraints", True,
                               "CA:FALSE, pathlen:0"),
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
    ca.sign(key, config_cert['hashalgorithm'])
    return ca, key

if __name__ == "__main__":
    sys.stdout.write("Certerator v0.1-pre1\n")
    sys.stdout.write("Stuart Morgan (@ukstufus) <stuart.morgan@mwrinfosecurity.com>\n\n")
    sys.stdout.flush()

    try:
        config_ca, config_cert = certerator_config()
    
        # Firstly, sort out the CA file
        if os.path.isfile(config_ca['cert_filename']) and os.path.isfile(config_ca['cert_key']):
            sys.stdout.write("Reusing "+config_ca['cert_filename']+" as the CA\n")
            ca_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, file(config_ca['cert_filename']).read())
            ca_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, file(config_ca['cert_key']).read())
        else:
            sys.stdout.write("Generating new CA...")
            sys.stdout.flush()
            ca_cert, ca_key = generate_ca(config_ca)
            sys.stdout.write("..done\n")
            open(config_ca['cert_filename'], "w").write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, ca_cert))
            open(config_ca['cert_key'], "w").write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, ca_key))

        # Now sort out the signing certificate
        if os.path.isfile(config_cert['cert_filename']) and os.path.isfile(config_cert['cert_key']):
            sys.stdout.write("Reusing "+config_cert['cert_filename']+" as the signing certificate\n")
            cert_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, file(config_cert['cert_filename']).read())
            cert_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, file(config_cert['cert_key']).read())
        else:
            sys.stdout.write("Generating new signing certificate...")
            sys.stdout.flush()
            cert_cert, cert_key = generate_certificate(config_cert)
            sys.stdout.write("..done\n")
            open(config_cert['cert_filename'], "w").write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_cert))
            open(config_cert['cert_key'], "w").write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, cert_key))
        sys.exit(0)

    except Exception as e:
        sys.stderr.write("Error: %s\n" % e)
        exit(1)
