#! /usr/bin/python

from __future__ import print_function

import sys
import os
import os.path
import time
import datetime
import getpass
from OpenSSL import crypto


HASH_ALGORITHM = 'sha256'
TERM_OF_VALIDITY = 3  # years


if os.path.isfile('cacert/cacert.key') or os.path.isfile('cacert/cacert.crt'):
    r = raw_input('warning: CA certificate is already exists. ' \
                      'Overwrite it? [y/N] ')
    if not r.lower() == 'y':
        exit(0)


attrs = []
attrs.append(('C', raw_input('C=')))
attrs.append(('L', raw_input('L=')))
attrs.append(('O', raw_input('O=')))
attrs.append(('OU', raw_input('OU=')))
attrs.append(('CN', raw_input('CN=')))
cdp = raw_input('CRL distribution point: ')

dn = []
t = []
for (k,v) in attrs:
    if v:
        dn.append((k,v))
        t.append('{}={}'.format(k,v))
dn_str = ','.join(t)

print('\nDN: ' + dn_str)
print('CDP: ' + cdp)
r = raw_input('Issue this CA certificate? [y/N] ')
if not r.lower() == 'y':
    exit(0)


while True:
    pp = getpass.getpass('Passphrase: ')
    if len(pp) < 8:
        print('error: Passphrase must be 8 or more charactors.',
              file=sys.stderr)
        continue
    pp2 = getpass.getpass('Confirm Passphrase: ')
    if pp == pp2:
        break
    print('error: Passphrases are not match.', file=sys.stderr)


key = crypto.PKey()
key.generate_key(crypto.TYPE_RSA, 2048)

req = crypto.X509Req()
sub = req.get_subject()
for (k,v) in dn:
    if v:
        setattr(sub, k, v)
req.set_pubkey(key)
req.sign(key, HASH_ALGORITHM)

today = datetime.datetime.utcnow()
expire = today.replace(today.year+TERM_OF_VALIDITY) + datetime.timedelta(15)

cert = crypto.X509()
cert.set_version(2)
cert.set_serial_number(int(time.time()))
cert.set_notBefore(today.strftime('%Y%m%d000000Z'))
cert.set_notAfter(expire.strftime('%Y%m%d000000Z'))
cert.set_issuer(req.get_subject())
cert.set_subject(req.get_subject())
cert.set_pubkey(req.get_pubkey())
if cdp:
    ext = crypto.X509Extension('crlDistributionPoints', False, 'URI:'+cdp)
    cert.add_extensions([ext])
ext1 = crypto.X509Extension('basicConstraints', True, 'CA:TRUE')
ext2 = crypto.X509Extension('keyUsage', True, 'keyCertSign, cRLSign')
ext3 = crypto.X509Extension('extendedKeyUsage', False,
                            'serverAuth, clientAuth')
cert.add_extensions([ext1, ext2, ext3])
cert.sign(key, HASH_ALGORITHM)


dirs = ['cacert', 'crl', 'certs']
for d in dirs:
    if not os.path.isdir(d):
        os.mkdir(d)

r = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
f = open('cacert/cacert.crt', 'w')
f.write(r)
f.close()

r = crypto.dump_privatekey(crypto.FILETYPE_PEM, key, 'AES256', pp)
f = open('cacert/cacert.key', 'w')
f.write(r)
f.close()

os.chmod('cacert/cacert.key', 0600)
