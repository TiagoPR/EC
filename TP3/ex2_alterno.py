from typing import List, Tuple
import hashlib
import os
from functools import reduce

class ShakeStream:
	def __init__(self, digestfn) -> None:
		# digestfn is anything we can call repeatedly with different lengths
		self.digest = digestfn
		self.buf = self.digest(32) # arbitrary starting length
		self.offset = 0
	
	def read(self, n: int) -> bytes:
		# double the buffer size until we have enough
		while self.offset + n > len(self.buf):
			self.buf = self.digest(len(self.buf) * 2)
		res = self.buf[self.offset:self.offset + n]
		self.offset += n
		return res


if __name__ == "__main__":
	from hashlib import shake_128

	a = ShakeStream(shake_128(b"hello").digest)
	foo = a.read(17) + a.read(5) + a.read(57) + a.read(1432) + a.read(48)
	bar = shake_128(b"hello").digest(17 + 5 + 57 + 1432 + 48)
	assert(foo == bar)

n = 256
q = 3329

DEFAULT_PARAMETERS = {
    "kyber_512" : {
        "k" : 2,
        "eta_1" : 3,
        "eta_2" : 2,
        "du" : 10,
        "dv" : 4,
    },
    "kyber_768" : {
        "k" : 3,
        "eta_1" : 2,
        "eta_2" : 2,
        "du" : 10,
        "dv" : 4,
    },
    "kyber_1024" : {
        "k" : 4,
        "eta_1" : 2,
        "eta_2" : 2,
        "du" : 11,
        "dv" : 5,
    }
}

def bitrev7(n: int) -> int:
	return int(f"{n:07b}"[::-1], 2)  # gross but it works

# can be reused for NTT representatives
def poly256_add(a: List[int], b: List[int]) -> List[int]:
	return [(x + y) % q for x, y in zip(a, b)]

def poly256_sub(a: List[int], b: List[int]) -> List[int]:
	return [(x - y) % q for x, y in zip(a, b)]

# naive O(n^2) multiplication algorithm for testing/comparison purposes.
# this is not used for the main impl.
def poly256_slow_mul(self, a: List[int], b: List[int]) -> List[int]:
	c = [0] * 511

	# textbook multiplication, without carry
	for i in range(256):
		for j in range(256):
			c[i+j] = (c[i+j] + a[j] * b[i]) % q

	# now for reduction mod X^256 + 1
	for i in range(255):
		c[i] = (c[i] - c[i+256]) % q
		# we could explicitly zero c[i+256] here, but there's no need...
	
	# ...because we're about to truncate c
	return c[:256]


ZETA = [pow(17, bitrev7(k), q) for k in range(128)] # used in ntt and ntt_inv
GAMMA = [pow(17, 2*bitrev7(k)+1, q) for k in range(128)] # used in ntt_mul

    
# by the way, this is O(n logn)
def ntt(f_in: List[int]) -> List[int]:
    f_out = f_in.copy()
    k = 1
    for log2len in range(7, 0, -1):
        length = 2**log2len
        for start in range(0, 256, 2 * length):
            zeta = ZETA[k]
            k += 1
            for j in range(start, start + length):
                t = (zeta * f_out[j + length]) % q
                f_out[j + length] = (f_out[j] - t) % q
                f_out[j] = (f_out[j] + t) % q
    return f_out


# so is this
def ntt_inv(f_in: List[int]) -> List[int]:
    f_out = f_in.copy()
    k = 127
    for log2len in range(1, 8):
        length = 2**log2len
        for start in range(0, 256, 2 * length):
            zeta = ZETA[k]
            k -= 1
            for j in range(start, start + length):
                t = f_out[j]
                f_out[j] = (t + f_out[j + length]) % q
                f_out[j + length] = (zeta * (f_out[j + length] - t)) % q

    for i in range(256):
        f_out[i] = (f_out[i] * 3303) % q  # 3303 == pow(128, -1, q)

    return f_out

ntt_add = poly256_add  # it's just elementwise addition

# and this is just O(n)
def ntt_mul(a: List[int], b: List[int]) -> List[int]:
    c = []
    for i in range(128):
        a0, a1 = a[2 * i: 2 * i + 2]
        b0, b1 = b[2 * i: 2 * i + 2]
        c.append((a0 * b0 + a1 * b1 * GAMMA[i]) % q)
        c.append((a0 * b1 + a1 * b0) % q)
    return c


class Kyber:
    def __init__(self, parameter_set) :
        self.k = parameter_set["k"]
        self.eta_1 = parameter_set["eta_1"]
        self.eta_2 = parameter_set["eta_2"]
        self.du = parameter_set["du"]
        self.dv = parameter_set["dv"]

    # crypto functions

    def mlkem_prf(self, eta: int, data: bytes, b: int) -> bytes:
        return hashlib.shake_256(data + bytes([b])).digest(64 * eta)

    def mlkem_xof(self, data: bytes, i: int, j: int) -> ShakeStream:
        return ShakeStream(hashlib.shake_128(data + bytes([i, j])).digest)

    def mlkem_hash_H(self, data: bytes) -> bytes:
        return hashlib.sha3_256(data).digest()

    def mlkem_hash_J(self, data: bytes) -> bytes:
        return hashlib.shake_256(data).digest(32)

    def mlkem_hash_G(self, data: bytes) -> bytes:
        return hashlib.sha3_512(data).digest()


    # encode/decode logic

    def bits_to_bytes(self,bits: List[int]) -> bytes:
        assert(len(bits) % 8 == 0)
        return bytes(
            sum(bits[i + j] << j for j in range(8))
            for i in range(0, len(bits), 8)
        )

    def bytes_to_bits(self,data: bytes) -> List[int]:
        bits = []
        for word in data:
            for i in range(8):
                bits.append((word >> i) & 1)
        return bits

    def byte_encode(self,d: int, f: List[int]) -> bytes:
        assert(len(f) == 256)
        bits = []
        for a in f:
            for i in range(d):
                bits.append((a >> i) & 1)
        return self.bits_to_bytes(bits)

    def byte_decode(self, d: int, data: bytes) -> List[int]:
        bits = self.bytes_to_bits(data)
        return [sum(bits[i * d + j] << j for j in range(d)) for i in range(256)]

    def compress(self, d: int, x: List[int]) -> List[int]:
        return [(((n * 2**d) + q // 2 ) // q) % (2**d) for n in x]

    def decompress(self, d: int, x: List[int]) -> List[int]:
        return [(((n * q) + 2**(d-1) ) // 2**d) % q for n in x]


    # sampling

    def sample_ntt(self, xof: ShakeStream):
        res = []
        while len(res) < 256:
            a, b, c = xof.read(3)
            d1 = ((b & 0xf) << 8) | a
            d2 = c << 4 | b >> 4
            if d1 < q:
                res.append(d1)
            if d2 < q and len(res) < 256:
                res.append(d2)
        return res


    def sample_poly_cbd(self,eta: int, data: bytes) -> List[int]:
        assert(len(data) == 64 * eta)
        bits = self.bytes_to_bits(data)
        f = []
        for i in range(256):
            x = sum(bits[2*i*eta+j] for j in range(eta))
            y = sum(bits[2*i*eta+eta+j] for j in range(eta))
            f.append((x - y) % q)
        return f


    # K-PKE

    def kpke_keygen(self, seed: bytes=None) -> Tuple[bytes, bytes]:
        d = os.urandom(32) if seed is None else seed
        ghash = self.mlkem_hash_G(d)
        rho, sigma = ghash[:32], ghash[32:]

        ahat = []
        for i in range(self.k):
            row = []
            for j in range(self.k):
                row.append(self.sample_ntt(self.mlkem_xof(rho, i, j)))
            ahat.append(row)
        
        shat = [
            ntt(self.sample_poly_cbd(self.eta_1, self.mlkem_prf(self.eta_1, sigma, i)))
            for i in range(self.k)
        ]
        ehat = [
            ntt(self.sample_poly_cbd(self.eta_1, self.mlkem_prf(self.eta_1, sigma, i+self.k)))
            for i in range(self.k)
        ]
        that = [ # t = a * s + e
            reduce(ntt_add, [
                ntt_mul(ahat[j][i], shat[j])
                for j in range(self.k)
            ] + [ehat[i]])
            for i in range(self.k)
        ]
        ek_pke = b"".join(self.byte_encode(12, s) for s in that) + rho
        dk_pke = b"".join(self.byte_encode(12, s) for s in shat)
        return ek_pke, dk_pke


    def kpke_encrypt(self, ek_pke: bytes, m: bytes, r: bytes) -> bytes:
        that = [self.byte_decode(12, ek_pke[i*128*self.k:(i+1)*128*self.k]) for i in range(self.k)]
        rho = ek_pke[-32:]

        # this is identical to as in kpke_keygen
        ahat = []
        for i in range(self.k):
            row = []
            for j in range(self.k):
                row.append(self.sample_ntt(self.mlkem_xof(rho, i, j)))
            ahat.append(row)
        
        rhat = [
            ntt(self.sample_poly_cbd(self.eta_1, self.mlkem_prf(self.eta_1, r, i)))
            for i in range(self.k)
        ]
        e1 = [
            self.sample_poly_cbd(self.eta_2, self.mlkem_prf(self.eta_2, r, i+self.k))
            for i in range(self.k)
        ]
        e2 = self.sample_poly_cbd(self.eta_2, self.mlkem_prf(self.eta_2, r, 2*self.k))

        u = [ # u = ntt-1(AT*r)+e1
            poly256_add(ntt_inv(reduce(ntt_add, [
                ntt_mul(ahat[i][j], rhat[j]) # note that i,j are reversed here
                for j in range(self.k)
            ])), e1[i])
            for i in range(self.k)
        ]
        mu = self.decompress(1, self.byte_decode(1, m))
        v = poly256_add(ntt_inv(reduce(ntt_add, [
            ntt_mul(that[i], rhat[i])
            for i in range(self.k)
        ])), poly256_add(e2, mu))

        c1 = b"".join(self.byte_encode(self.du, self.compress(self.du, u[i])) for i in range(self.k))
        c2 = self.byte_encode(self.dv, self.compress(self.dv, v))
        return c1 + c2


    def kpke_decrypt(self,dk_pke: bytes, c: bytes) -> bytes:
        c1 = c[:32*self.du*self.k]
        c2 = c[32*self.du*self.k:]
        u = [
            self.decompress(self.du, self.byte_decode(self.du, c1[i*32*self.du:(i+1)*32*self.du]))
            for i in range(self.k)
        ]
        v = self.decompress(self.dv, self.byte_decode(self.dv, c2))
        shat = [self.byte_decode(12, dk_pke[i*384:(i+1)*384]) for i in range(self.k)]
        # NOTE: the comment in FIPS203 seems wrong here?
        # it says "NTT−1 and NTT invoked k times", but I think NTT−1 is only invoked once.
        w = poly256_sub(v, ntt_inv(reduce(ntt_add, [
            ntt_mul(shat[i], ntt(u[i]))
            for i in range(self.k)
        ])))
        m = self.byte_encode(1, self.compress(1, w))
        return m


    # KEM time

    def mlkem_keygen(self,seed1=None, seed2=None):
        z = os.urandom(32) if seed1 is None else seed1
        ek_pke, dk_pke = self.kpke_keygen(seed2)
        ek = ek_pke
        dk = dk_pke + ek + self.mlkem_hash_H(ek) + z
        return ek, dk


    def mlkem_encaps(self, ek: bytes, seed=None) -> Tuple[bytes, bytes]:
        # TODO !!!! input validation !!!!!!!
        m = os.urandom(32) if seed is None else seed
        ghash = self.mlkem_hash_G(m + self.mlkem_hash_H(ek))
        k = ghash[:32]
        r = ghash[32:]
        c = self.kpke_encrypt(ek, m, r)
        return k, c


    def mlkem_decaps(self, c: bytes, dk: bytes) -> bytes:
        # TODO !!!! input validation !!!!!!!
        dk_pke = dk[:384*self.k]
        ek_pke = dk[384*self.k : 768*self.k + 32]
        h = dk[768*self.k + 32 : 768*self.k + 64]
        z = dk[768*self.k + 64 : 768*self.k + 96]
        mdash = self.kpke_decrypt(dk_pke, c)
        ghash = self.mlkem_hash_G(mdash + h)
        kdash = ghash[:32]
        rdash = ghash[32:]
        # NOTE: J() has unnecessary second argument in the spec???
        kbar = self.mlkem_hash_J(z + c)
        cdash = self.kpke_encrypt(ek_pke, mdash, rdash)
        if cdash != c:
            # I suppose this branch ought to be constant-time, but that's already out the window with this impl
            #print("did not match") # XXX: what does implicit reject mean? I suppose it guarantees it fails in a not-attacker-controlled way?
            return kbar
        return kdash


kyber = Kyber(DEFAULT_PARAMETERS["kyber_768"])
ek_pke, dk_pke = kyber.kpke_keygen(b"SEED"*8)

msg = b"This is a demonstration message."
ct = kyber.kpke_encrypt(ek_pke, msg, b"RAND"*8)
pt = kyber.kpke_decrypt(dk_pke, ct)
print(pt)
assert(pt == msg)

ek, dk = kyber.mlkem_keygen()
k1, c = kyber.mlkem_encaps(ek)
print("encapsulated:", k1.hex())

k2 = kyber.mlkem_decaps(c, dk)
print("decapsulated:", k2.hex())

assert(k1 == k2)