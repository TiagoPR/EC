import hashlib

# A class representing a field element
class Field:
    # Construct number x (mod p)
    def __init__(self, x, p):
        self.__x = x % p
        self.__p = p

    # Field addition. The fields must match.
    def __add__(self, y):
        self.__check_fields(y)
        return Field((self.__x + y.__x) % self.__p, self.__p)

    # Field subtraction. The fields must match.
    def __sub__(self, y):
        self.__check_fields(y)
        return Field((self.__p + self.__x - y.__x) % self.__p, self.__p)

    # Field negation
    def __neg__(self):
        return Field((self.__p - self.__x) % self.__p, self.__p)

    # Field multiplication. The fields must match.
    def __mul__(self, y):
        self.__check_fields(y)
        return Field((self.__x * y.__x) % self.__p, self.__p)

    # Field division. The fields must match.
    def __truediv__(self, y):
        return self * y.inv()

    # Field inverse (inverse of 0 is 0)
    def inv(self):
        return Field(pow(self.__x, self.__p - 2, self.__p), self.__p)

    # Check that fields of self and y are the same.
    def __check_fields(self, y):
        if type(y) is not Field or self.__p != y.__p:
            raise ValueError("Fields don't match")

# A point on Edwards25519 curve
class Edwards25519Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y
        self.z = Field(1, 2 ** 255 - 19)

    # Point addition
    def __add__(self, y):
        tmp = self.zero_elem()
        zcp = self.z * y.z
        A = (self.y - self.x) * (y.y - y.x)
        B = (self.y + self.x) * (y.y + y.x)
        C = (Field(-1, 2 ** 255 - 19) + Field(-1, 2 ** 255 - 19)) * self.t * y.t
        D = zcp + zcp
        E, H = B - A, B + A
        F, G = D - C, D + C
        tmp.x, tmp.y, tmp.z, tmp.t = E * F, G * H, F * G, E * H
        return tmp

    # Point doubling
    def double(self):
        tmp = self.zero_elem()
        x1s, y1s, z1s = self.x * self.x, self.y * self.y, self.z * self.z
        xys = self.x + self.y
        F = x1s + y1s
        J = F - (z1s + z1s)
        tmp.x, tmp.y, tmp.z = (xys * xys - x1s - y1s) * J, F * (x1s - y1s), F * J
        return tmp

    # Construct a neutral point on this curve
    def zero_elem(self):
        return Edwards25519Point(Field(0, 2 ** 255 - 19), Field(1, 2 ** 255 - 19))

# PureEdDSA scheme
class PureEdDSA:
    def __init__(self, properties):
        self.B = properties["B"]
        self.l = self.B.l()
        self.b = self.B.b()

    # Generate a key pair
    def keygen(self, privkey):
        khash = self.H(privkey)
        a = int.from_bytes(khash[:self.b // 8], byteorder="little") % self.l
        return privkey, (self.B * a).encode()

    # Sign with key pair
    def sign(self, privkey, pubkey, msg):
        khash = self.H(privkey)
        a = int.from_bytes(khash[:self.b // 8], byteorder="little") % self.l
        seed = khash[self.b // 8:]
        r = int.from_bytes(self.H(seed + msg), byteorder="little") % self.l
        R = (self.B * r).encode()
        h = int.from_bytes(self.H(R + pubkey + msg), byteorder="little") % self.l
        S = ((r + h * a) % self.l).to_bytes(self.b // 8, byteorder="little")
        return R + S

    # Verify signature with public key
    def verify(self, pubkey, msg, sig):
        if len(sig) != self.b // 4:
            return False
        Rraw, Sraw = sig[:self.b // 8], sig[self.b // 8:]
        R, S = self.B.decode(Rraw), int.from_bytes(Sraw, byteorder="little")
        if R is None or S >= self.l:
            return False
        A = self.B.decode(pubkey)
        if A is None:
            return False
        h = int.from_bytes(self.H(Rraw + pubkey + msg), byteorder="little") % self.l
        rhs = R + (A * h)
        lhs = self.B * S
        for _ in range(self.c):
            lhs = lhs.double()
            rhs = rhs.double()
        return lhs == rhs

def Ed25519_inthash(data):
    return hashlib.sha512(data).digest()

# The base PureEdDSA schemes
pEd25519 = PureEdDSA({"B": Edwards25519Point(Field(1, 2 ** 255 - 19), Field(4, 2 ** 255 - 19))})

# EdDSA scheme
class EdDSA:
    def __init__(self, pure_scheme):
        self.__pure = pure_scheme

    # Generate a key pair
    def keygen(self, privkey):
        return self.__pure.keygen(privkey)

    # Sign message msg using specified key pair
    def sign(self, privkey, pubkey, msg):
        return self.__pure.sign(privkey, pubkey, msg)

    # Verify signature sig on message msg using public key pubkey
    def verify(self, pubkey, msg, sig):
        return self.__pure.verify(pubkey, msg, sig)

def eddsa_obj(name):
    if name == "Ed25519":
        return EdDSA(pEd25519)
    raise NotImplementedError("Algorithm not implemented")

# Example usage:
ed25519 = eddsa_obj("Ed25519")
priv_key, pub_key = ed25519.keygen(b"my_private_key")
signature = ed25519.sign(priv_key, pub_key)
