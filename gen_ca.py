#! /usr/bin/python3

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
    r = input('warning: CA certificate is already exists. ' \
              'Overwrite it? [y/N] ')
    if not r.lower() == 'y':
        exit(0)


attrs = []
attrs.append(('C', input('C=')))
attrs.append(('L', input('L=')))
attrs.append(('O', input('O=')))
attrs.append(('OU', input('OU=')))
attrs.append(('CN', input('CN=')))
cdp = input('CRL distribution point: ')

dn = []
t = []
for (k,v) in attrs:
    if v:
        dn.append((k,v))
        t.append('{}={}'.format(k,v))
dn_str = ','.join(t)

print('\nDN: ' + dn_str)
print('CDP: ' + cdp)
r = input('Issue this CA certificate? [y/N] ')
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
cert.set_notBefore(today.strftime('%Y%m%d000000Z').encode())
cert.set_notAfter(expire.strftime('%Y%m%d000000Z').encode())
cert.set_issuer(req.get_subject())
cert.set_subject(req.get_subject())
cert.set_pubkey(req.get_pubkey())
if cdp:
    ext = crypto.X509Extension(b'crlDistributionPoints', False,
                               b'URI:'+cdp.encode())
    cert.add_extensions([ext])
ext1 = crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE')
ext2 = crypto.X509Extension(b'keyUsage', True, b'keyCertSign, cRLSign')
ext3 = crypto.X509Extension(b'extendedKeyUsage', False,
                            b'serverAuth, clientAuth')
cert.add_extensions([ext1, ext2, ext3])
cert.sign(key, HASH_ALGORITHM)


dirs = ['cacert', 'crl', 'certs']
for d in dirs:
    if not os.path.isdir(d):
        os.mkdir(d)

r = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
f = open('cacert/cacert.crt', 'w')
f.write(r.decode())
f.close()

r = crypto.dump_privatekey(crypto.FILETYPE_PEM, key, 'AES256', pp.encode())
f = open('cacert/cacert.key', 'w')
f.write(r.decode())
f.close()

os.chmod('cacert/cacert.key', 0o600)
