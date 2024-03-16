#
import sys
import binascii

from eddsa2 import Ed25519, PureEdDSA, Edwards25519Point, Ed25519_inthash, EdDSA

def munge_string(s, pos, change):
    return (s[:pos] +
            int.to_bytes(s[pos] ^ change, 1, "little") +
            s[pos+1:])

# Read a file in the format of
# http://ed25519.cr.yp.to/python/sign.input
lineno = 0
while True:
    line = open("sign.input", "r").read()
    if not line:
        break
    lineno = lineno + 1
    print(lineno)
    fields = line.split(":")
    secret = (binascii.unhexlify(fields[0]))[:32]
    public = binascii.unhexlify(fields[1])
    msg = binascii.unhexlify(fields[2])
    signature = binascii.unhexlify(fields[3])[:64]

    pEd25519=PureEdDSA({\
    "B":Edwards25519Point.stdbase(),\
    "H":Ed25519_inthash\
    })
    Ed25519 = EdDSA(pEd25519,None)
    privkey,pubkey = Ed25519.keygen(secret)
    assert public == pubkey
    assert signature == Ed25519.sign(privkey, pubkey, msg)
    assert Ed25519.verify(public, msg, signature)
    if len(msg) == 0:
        bad_msg = b"x"
    else:
        bad_msg = munge_string(msg, len(msg) // 3, 4)
    assert not Ed25519.verify(public,bad_msg,signature)
    assert not Ed25519.verify(public, msg, munge_string(signature,20,8))
    assert not Ed25519.verify(public,msg,munge_string(signature,40,16))