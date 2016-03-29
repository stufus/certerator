#/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  Certerator 0.1-pre1
#  Stuart Morgan <stuart.morgan@mwrinfosecurity.com> @ukstufus
#
#  This will generate a CA and certificate (signed by the CA) which can be used
#  for code signing. It will also display the commands to run using both osslsigncode
#  or signtool.exe depending on preference.
#
#  This has been used successfully on simulated attack engagements to disguise
#  the presence of an implant.
#

import os
import sys
from OpenSSL import crypto

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
    ca['cert_der'] = "ca.cer"
    ca['cert_p12'] = "ca.p12"
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
    cert['cert_filename'] = "cert.pem"
    cert['cert_key'] = "cert.key"
    cert['cert_p12'] = "cert.p12"
    cert['serial'] = 234567
    cert['validfrom'] = "20150101000000Z"
    cert['validto'] = "20180101000000Z"
    cert['keyfilesize'] = 4096
    cert['hashalgorithm'] = "sha256"

    return ca, cert

def banner():
    sys.stdout.write("\n")
    sys.stdout.write("       .mMMMMMm.             MMm    M   WW   W   WW   RRRRR\n")
    sys.stdout.write("      mMMMMMMMMMMM.           MM   MM    W   W   W    R   R\n")
    sys.stdout.write("     /MMMM-    -MM.           MM   MM    W   W   W    R   R\n")
    sys.stdout.write("    /MMM.    _  \/  ^         M M M M     W W W W     RRRR\n")
    sys.stdout.write("    |M.    aRRr    /W|        M M M M     W W W W     R  R\n")
    sys.stdout.write("    \/  .. ^^^   wWWW|        M  M  M      W   W      R   R\n")
    sys.stdout.write("       /WW\.  .wWWWW/         M  M  M      W   W      R    R\n")
    sys.stdout.write("       |WWWWWWWWWWW/\n")
    sys.stdout.write("         .WWWWWW.      Certerator (Code Signing Certificate Generator)\n")
    sys.stdout.write("                        stuart.morgan@mwrinfosecurity.com | @ukstufus\n")
    sys.stdout.write("\n")
    sys.stdout.flush()

def openssl_generate_privatekey(size):
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, size)
    return key

def generate_ca(config_ca):
    ca = crypto.X509()
    ca.set_version(2)
    ca.set_serial_number(config_ca['serial'])
    ca_subj = ca.get_subject()
    if 'commonName' in config_ca:
        ca_subj.commonName = config_ca['commonName']
    if 'stateOrProvinceName' in config_ca:
        ca_subj.stateOrProvinceName = config_ca['stateOrProvinceName']
    if 'localityName' in config_ca:
        ca_subj.localityName = config_ca['localityName']
    if 'organizationName' in config_ca:
        ca_subj.organizationName = config_ca['organizationName']
    if 'organizationalUnitName' in config_ca:
        ca_subj.organizationalUnitName = config_ca['organizationalUnitName']
    if 'emailAddress' in config_ca:
        ca_subj.emailAddress = config_ca['emailAddress']
    if 'countryName' in config_ca:
        ca_subj.countryName = config_ca['countryName']
    if 'validfrom' in config_ca:
        ca.set_notBefore(config_ca['validfrom'])
    if 'validto' in config_ca:
        ca.set_notAfter(config_ca['validto'])
    key = openssl_generate_privatekey(config_ca['keyfilesize'])
    ca.add_extensions([
        crypto.X509Extension("basicConstraints", True, "CA:TRUE, pathlen:1"),
        crypto.X509Extension("keyUsage", False, "keyCertSign, cRLSign"),
        crypto.X509Extension("subjectKeyIdentifier", False, "hash", subject=ca),
    ])
    ca.add_extensions([
        crypto.X509Extension("authorityKeyIdentifier", False, "keyid:always",issuer=ca)
    ])
    ca.set_issuer(ca.get_subject())
    ca.set_pubkey(key)
    ca.sign(key, config_ca['hashalgorithm'])
    return ca, key

def colourise(string,colour):
    return "\033["+colour+"m"+string+"\033[0m"

def generate_certificate(config_cert, ca, cakey):
    # Generate the private key
    key = openssl_generate_privatekey(config_cert['keyfilesize'])

    # Generate the certificate request
    req = crypto.X509Req()
    req_subj = req.get_subject()
    if 'commonName' in config_cert:
        req_subj.commonName = config_cert['commonName']
    if 'stateOrProvinceName' in config_cert:
        req_subj.stateOrProvinceName = config_cert['stateOrProvinceName']
    if 'localityName' in config_cert:
        req_subj.localityName = config_cert['localityName']
    if 'organizationName' in config_cert:
        req_subj.organizationName = config_cert['organizationName']
    if 'organizationalUnitName' in config_cert:
        req_subj.organizationalUnitName = config_cert['organizationalUnitName']
    if 'emailAddress' in config_cert:
        req_subj.emailAddress = config_cert['emailAddress']
    if 'countryName' in config_cert:
        req_subj.countryName = config_cert['countryName']

    req.set_pubkey(key)
    req.sign(key, config_cert['hashalgorithm'])

    # Now generate the certificate itself
    cert = crypto.X509()
    cert.set_version(2)
    cert.set_serial_number(config_cert['serial'])
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.set_issuer(ca.get_subject())

    if 'validfrom' in config_cert:
        cert.set_notBefore(config_cert['validfrom'])
    if 'validto' in config_cert:
        cert.set_notAfter(config_cert['validto'])

    cert.add_extensions([
        crypto.X509Extension("basicConstraints", True, "CA:FALSE"),
        crypto.X509Extension("keyUsage", False, "digitalSignature"),
        crypto.X509Extension("extendedKeyUsage", False, "codeSigning,msCTLSign,timeStamping,msCodeInd,msCodeCom"),
        crypto.X509Extension("subjectKeyIdentifier", False, "hash", subject=cert),
        crypto.X509Extension("authorityKeyIdentifier", False, "keyid:always", issuer=ca)
    ])

    cert.sign(cakey, config_cert['hashalgorithm'])
    return cert, key

def make_p12(cert,key):
    p12 = crypto.PKCS12()
    p12.set_certificate(cert)
    p12.set_privatekey(key)
    return p12.export('mwr')

if __name__ == "__main__":
    banner()
    try:
        config_ca, config_cert = certerator_config()
    
        # Firstly, sort out the CA file
        if os.path.isfile(config_ca['cert_filename']) and os.path.isfile(config_ca['cert_key']):
            sys.stdout.write(colourise("Reusing "+config_ca['cert_filename']+" as the CA\n",'0;36'))
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, file(config_ca['cert_filename']).read())
            ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, file(config_ca['cert_key']).read())
            sys.stdout.write(colourise(" SHA1 CA Fingerprint: "+ca_cert.digest('sha1')+"\n", '0;32'))
        else:
            sys.stdout.write(colourise("Generating new CA...",'0;32'))
            sys.stdout.flush()
            ca_cert, ca_key = generate_ca(config_ca)
            sys.stdout.write(colourise("..done\n",'0;32'))
            open(config_ca['cert_filename'], "w").write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))
            open(config_ca['cert_der'], "wb").write(crypto.dump_certificate(crypto.FILETYPE_ASN1, ca_cert))
            open(config_ca['cert_key'], "w").write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key))
            open(config_ca['cert_p12'], "wb").write(make_p12(ca_cert,ca_key))
            sys.stdout.write(colourise(" Written PEM CA certificate to "+config_ca['cert_filename']+"\n", '0;32'))
            sys.stdout.write(colourise(" Written DER CA certificate to "+config_ca['cert_der']+"\n", '0;32'))
            sys.stdout.write(colourise(" Written CA private key to "+config_ca['cert_key']+"\n", '0;32'))
            sys.stdout.write(colourise(" Written CA PKCS12 (private key and certificate) to "+config_ca['cert_p12']+"\n", '0;32'))
            sys.stdout.write(colourise(" SHA1 CA Fingerprint: "+ca_cert.digest('sha1')+"\n", '0;32'))
            
        # Now sort out the signing certificate
        if os.path.isfile(config_cert['cert_filename']) and os.path.isfile(config_cert['cert_key']):
            sys.stdout.write(colourise("Reusing "+config_cert['cert_filename']+" as the code signing certificate\n",'0;36'))
            cert_cert = crypto.load_certificate(crypto.FILETYPE_PEM, file(config_cert['cert_filename']).read())
            cert_key = crypto.load_privatekey(crypto.FILETYPE_PEM, file(config_cert['cert_key']).read())
            sys.stdout.write(colourise(" SHA1 Cert Fingerprint: "+cert_cert.digest('sha1')+"\n", '0;32'))
        else:
            sys.stdout.write(colourise("Generating new signing certificate...",'0;32'))
            sys.stdout.flush()
            cert_cert, cert_key = generate_certificate(config_cert,ca_cert,ca_key)
            sys.stdout.write(colourise("..done\n",'0;32'))
            open(config_cert['cert_filename'], "w").write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert_cert))
            open(config_cert['cert_key'], "w").write(crypto.dump_privatekey(crypto.FILETYPE_PEM, cert_key))
            open(config_cert['cert_p12'], "wb").write(make_p12(cert_cert,cert_key))
            sys.stdout.write(colourise(" Written PEM certificate to "+config_cert['cert_filename']+"\n", '0;32'))
            sys.stdout.write(colourise(" Written private key to "+config_cert['cert_key']+"\n", '0;32'))
            sys.stdout.write(colourise(" Written PKCS12 (private key and certificate) to "+config_cert['cert_p12']+"\n", '0;32'))
            sys.stdout.write(colourise(" SHA1 Cert Fingerprint: "+cert_cert.digest('sha1')+"\n", '0;32'))

        # Instructions
        sys.stdout.write("\n")
        sys.stdout.write(colourise("Linux/UNIX:\n",'0;31'))
        sys.stdout.write(colourise(" osslsigncode -pkcs12 "+config_cert['cert_p12']+" -pass mwr -in in.exe -out out.exe\n\n",'1;31'))
        sys.stdout.write(colourise("Windows:\n",'0;31'))
        sys.stdout.write(colourise(" signtool.exe sign /f "+config_cert['cert_p12']+" /p mwr in.exe\n\n", '1;31'))
        sys.exit(0)

    except Exception as e:
        sys.stderr.write("Error: %s\n" % e)
        sys.exit(1)
