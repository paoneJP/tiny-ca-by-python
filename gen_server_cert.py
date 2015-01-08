#! /usr/bin/python3

import sys
import os
import os.path
import time
import datetime
import getpass
from OpenSSL import crypto


HASH_ALGORITHM = 'sha256'
TERM_OF_VALIDITY = 1  # year


if not os.path.isfile('cacert/cacert.crt'):
    print('error: CA certificate is not found.', file=sys.stderr)
    exit(1)
r = open('cacert/cacert.crt').read()
cacert = crypto.load_certificate(crypto.FILETYPE_PEM, r)

if not os.path.isfile('cacert/cacert.key'):
    print('error: CA private key is not found.', file=sys.stderr)
    exit(1)
r = open('cacert/cacert.key').read()
retry = 3
while True:
    try:
        cakey = crypto.load_privatekey(crypto.FILETYPE_PEM, r)
        break
    except (crypto.Error, RuntimeError):
        retry = retry - 1
        if retry == 0:
            print('error: cannot read CA private key', file=sys.stderr)
            exit(1)


attrs = []
attrs.append(('C', input('C=')))
attrs.append(('L', input('L=')))
attrs.append(('O', input('O=')))
attrs.append(('OU', input('OU=')))
attrs.append(('CN', input('CN=')))

dn = []
t = []
for (k,v) in attrs:
    if v:
        dn.append((k,v))
        t.append('{}={}'.format(k,v))
dn_str = ','.join(t)

print('\nDN: ' + dn_str)
r = input('Issue this server certificate? [y/N] ')
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
cert.set_issuer(cacert.get_subject())
cert.set_subject(req.get_subject())
cert.set_pubkey(req.get_pubkey())
ext = None
for i in range(cacert.get_extension_count()):
    e = cacert.get_extension(i)
    if e.get_short_name() == 'crlDistributionPoints':
        ext = e
        break
if ext:
    cert.add_extensions([ext])
ext1 = crypto.X509Extension(b'basicConstraints', True, b'CA:FALSE')
ext2 = crypto.X509Extension(b'keyUsage', True,
                            b'digitalSignature, keyEncipherment')
ext3 = crypto.X509Extension(b'extendedKeyUsage', False,
                            b'serverAuth, clientAuth')
cert.add_extensions([ext1, ext2, ext3])
cert.sign(cakey, HASH_ALGORITHM)


name = '{}_{}'.format(cert.get_subject().CN, cert.get_serial_number())

r = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
f = open('certs/{}.crt'.format(name), 'w')
f.write(r.decode())
f.close()

r = crypto.dump_privatekey(crypto.FILETYPE_PEM, key, 'AES256', pp.encode())
f = open('certs/{}.key'.format(name), 'w')
f.write(r.decode())
f.close()

os.chmod('certs/{}.key'.format(name), 0o600)
