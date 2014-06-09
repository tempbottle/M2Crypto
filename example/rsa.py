#!/usr/bin/env python
# -*- coding=utf-8 -*-
#author: tempbottle#at#gmail.com
#file: rsa.py
 
from M2Crypto import RSA, BIO,m2
import binascii as ba
import time
import hashlib

priv_key = '''
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAzNzYLv8KNzyHSjlaXFvCpeOAnZuhKSgEcT6HzNMytqECfM8H
rfWXiu6K15ELz1RD4hpFlH7se9gBmUiy2y3pvkW9JggMf+JI34qUnVaV5SYwnx9Y
yF1LvTEN2/bGoxqYmo0+LyVzO+2ZRYszMHexgijil+FMzEyIbu6+/fT1S1dQcqf2
9dlP3lG09nkBGoe4rRjKtYtAUlUJusJBF+Lq8EJW2yMl2Iaf2TW30C8W+XARWCxr
cO6SqJoSvlsqjsARTQ2BTMe28J5UFZlcLedWg2VpqbyhzhteiVCraqczqOi2g/4E
Fz+7qTu+Qv3SGKIihVUhdSAJDzrankBHctssxQIDAQABAoIBAHsxKsdIEuqYeXrG
9nGntGtxXXxphAZtzA4VXjBrqIluVUKcdK/FifW/8LokvQdWUuP6jHD5ylfG019L
+lIXUAJdiZr/KBUXDF9wxGHBGa6MwpxNi2QhxlPk1cK6qUSXz8DQwt4zFRKqlIrf
ZE73C0WMNIbEsxv/weODqlKpJYDB0kmVwTIcpPSVQv965vpwlO9oobBncpDpWtcM
/VNCgXe6zEFrbsrF5r5Dl3aAE/MO/t/j4F3PRMMcHjqv10ds6rufTC8U/muKzqmM
KouAsVmSRNTxBuTHobUnSSLYne1wDbZCZtGzjOf7aru1a3lxDi1N2OzHEfRAJd9i
9MtNd5kCgYEA+uI1XLO0maloz6xYbOnGGx4er5FkguQATAiVb4lms6iAI1pPx+1p
ucagP2Qd1PgMXvbKNc7G9BwDP3/vp1h/Rh5Pud1ozC/7083coIRb3KhJXU5r/REg
9fiSKPFtMYbsWd+vKvO7ukHKVM0TMAtPLtkX7X3L347zp1cY1ZjMvRcCgYEA0Qpf
sdbLbSWUBiqi3nEeo7rGScznuWoLVwVB9BmFz+DgTYl6589pBRHNXLXc4rr+oqef
3bibTllyymrTLEbXliJfg1ftHRQcacbDlDwfDiqlkzOxBDcEoTQsIZFx0LmpxELR
btqDZ2eE1G0lbOkjj5U+ZZBovHDX6cmPA0dDJoMCgYAYJdXFCncDo063TntkYEv1
KD0D4RavkoqExv67MZp1CG7s+DBdqfhXLUsXTuegLA/kxBRKgZCcxmV5ozLKBLab
ZSd/WFRR8vxmMpZdzN+aqYgGNxolzZRCmJ5Y2oQMFFSDggg2NieHkfWLnAGQykXg
2Hx5G3aYGgZRwQxe4soyGQKBgH7FC8ONv1AxudMDiEHd1/bzDc0ztlN7O+VKCvU9
hSjL9zsOZLqvzcCFS0UuBQZ64HFDtm9/xK9/D14x6l6vl440yjec2u8HgzOilnkO
/MZalo7uiitEMkqQmTLCQYOTFKEw5FGVsprC7IrmpgumVyp8F5sAOIQO6uGcml4i
mVaBAoGBAJNdSjYNz/EyPgDW/cOQ50QWP/uiNHMUNgnyfhQPAyl6MROY8IA12786
6RfhNlIRj71ga0OlpOeTYZwel9zeW0NPdwLSRQuqsQyKInshsFK2P2fTQUPsmFLl
+rQuBr6xtzgDI2mf6w6EFthoabvwGRY6FerwurCwHjGuXhe0nJUW
-----END RSA PRIVATE KEY-----
'''

'''
mem = BIO.MemoryBuffer()
rsa = RSA.gen_key(2048,0x010001,lambda *arg:None)
rsa.save_pub_key_bio(mem)
rsa.save_key_bio(mem, None)
print mem.read_all()

print dir(rsa)

data = "data_"*20
cipher = rsa.private_encrypt(data, RSA.pkcs1_padding)

cipher2 = rsa.private_encrypt(data, RSA.pkcs1_padding)
print ba.hexlify(cipher),"\n"
print ba.hexlify(cipher2),"\n"
data2 = rsa.public_decrypt(cipher, RSA.pkcs1_padding)
print data,"\n"
print data2,"\n"


data = "data_"*20
cipher = rsa.public_encrypt(data, RSA.pkcs1_padding)

cipher2 = rsa.public_encrypt(data, RSA.pkcs1_padding)
print ba.hexlify(cipher),"\n"
print ba.hexlify(cipher2),"\n"
data2 = rsa.private_decrypt(cipher, RSA.pkcs1_padding)
print data,"\n"
print data2,"\n"
'''

rsa = RSA.load_key_bio(BIO.MemoryBuffer(priv_key))
data = ba.unhexlify('01')
print type(data[0])
data = hashlib.sha256(data).digest()
print ba.hexlify(data)

print "private encrypt pkcs1_padding"
cipher = rsa.private_encrypt(data, RSA.pkcs1_padding)
print ba.hexlify(cipher),"\n"
data2 = rsa.public_decrypt(cipher, RSA.pkcs1_padding)

print "\nprivate encrypt no_padding, left side 0\n"
data = ba.unhexlify('01')
data = hashlib.sha256(data).digest()
print "sha256 is ",ba.hexlify(data),len(data)
data = b'\x00'*(256-len(data)) + data #padding with 0
print len(data)
print ba.hexlify(data)
cipher = rsa.private_encrypt(data, RSA.no_padding)
s = ba.hexlify(cipher)
print ba.hexlify(cipher),"\n"
data2 = rsa.public_decrypt(cipher, RSA.no_padding)

print "\nprivate encrypt no_padding, right side 0\n"
data = ba.unhexlify('01')
data = hashlib.sha256(data).digest()
print "sha256 is ",ba.hexlify(data),len(data)
data = b''+data + b'\x00'*(256-len(data)) #padding with 0
print len(data)
print ba.hexlify(data)
cipher = rsa.private_encrypt(data, RSA.no_padding)
s = ba.hexlify(cipher)
print ba.hexlify(cipher),"\n"
data2 = rsa.public_decrypt(cipher, RSA.no_padding)

data = ba.unhexlify('01')
data = hashlib.sha256(data).digest()
print dir(rsa)
print ba.hexlify(rsa.sign(data, 'sha256'))
print "N:", m2.bn_to_hex(m2.mpi_to_bn(rsa.n))
print "E:", m2.bn_to_hex(m2.mpi_to_bn(rsa.e))
print "D:", m2.bn_to_hex(m2.mpi_to_bn(rsa.d))

exit()
# ===================================================================
'''
print "public encrypt pkcs1_padding\n"
cipher = rsa.public_encrypt(data, RSA.pkcs1_padding)
cipher2 = rsa.public_encrypt(data, RSA.pkcs1_padding)
print ba.hexlify(cipher),"\n"
print ba.hexlify(cipher2),"\n"
data2 = rsa.private_decrypt(cipher, RSA.pkcs1_padding)
'''
print(dir(RSA))
exit()

'''
# ===================================================================
data = "data_"*20
print "private encrypt sslv23_padding"
cipher = rsa.private_encrypt(data, RSA.sslv23_padding)

cipher2 = rsa.private_encrypt(data, RSA.sslv23_padding)
print ba.hexlify(cipher),"\n"
print ba.hexlify(cipher2),"\n"
data2 = rsa.public_decrypt(cipher, RSA.sslv23_padding)
print data,"\n"
print data2,"\n"

print "public encrypt sslv23_padding\n"
cipher = rsa.public_encrypt(data, RSA.sslv23_padding)

cipher2 = rsa.public_encrypt(data, RSA.sslv23_padding)
print ba.hexlify(cipher),"\n"
print ba.hexlify(cipher2),"\n"
data2 = rsa.private_decrypt(cipher, RSA.sslv23_padding)
print data,"\n"
print data2,"\n"
'''

# ===================================================================
data = ba.unhexlify('01')
print "private encrypt pkcs1_oaep_padding"
cipher = rsa.private_encrypt(data, RSA.pkcs1_oaep_padding)
print ba.hexlify(cipher),"\n"
print ba.hexlify(cipher2),"\n"
data2 = rsa.public_decrypt(cipher, RSA.pkcs1_oaep_padding)
print data,"\n"
print data2,"\n"

print "public encrypt pkcs1_oaep_padding\n"
cipher = rsa.public_encrypt(data, RSA.pkcs1_oaep_padding)
cipher2 = rsa.public_encrypt(data, RSA.pkcs1_oaep_padding)
print ba.hexlify(cipher),"\n"
print ba.hexlify(cipher2),"\n"
data2 = rsa.private_decrypt(cipher, RSA.pkcs1_oaep_padding)
print data,"\n"
print data2,"\n"