from cryptography.hazmat.primitives import hashes
from pickle import dumps

DEFAULT_PARAMETERS = {
    "kyber_512" : {
        "n" : 256,
        "k" : 2,
        "q" : 3329,
        "eta_1" : 3,
        "eta_2" : 2,
        "du" : 10,
        "dv" : 4,
    },
    "kyber_768" : {
        "n" : 256,
        "k" : 3,
        "q" : 3329,
        "eta_1" : 2,
        "eta_2" : 2,
        "du" : 10,
        "dv" : 4,
    },
    "kyber_1024" : {
        "n" : 256,
        "k" : 4,
        "q" : 3329,
        "eta_1" : 2,
        "eta_2" : 2,
        "du" : 11,
        "dv" : 5,
    }
}


# Implementação da Classe NTT (Number Theoretic Transform)
class NTT(object):
    def __init__(self, n=128, q=None):
        if not n in [32,64,128,256,512,1024,2048]:
            raise ValueError("Argumento inválido", n)
        self.n = n  
        if not q:
            self.q = 1 + 2*n
            while True:
                if (self.q).is_prime():
                    break
                self.q += 2*n
        else:
            # if q % (2*n) != 1:
            #     raise ValueError("O valor 'q' não verifica a condição NTT")
            self.q = q
        
        self.F = GF(self.q) ;  self.R = PolynomialRing(self.F, name="w")
        w = (self.R).gen()
        
        g = (w^n + 1)
        xi = g.roots(multiplicities=False)[-1]
        self.xi = xi
        rs = [xi^(2*i+1)  for i in range(n)] 
        self.base = crt_basis([(w - r) for r in rs])  
    
    def ntt(self,f):
        def _expand_(f): 
            u = f.list()
            return u + [0]*(self.n-len(u)) 
        
        def _ntt_(xi,N,f):
            if N==1:
                return f
            N_ = N/2 ; xi2 =  xi^2  
            f0 = [f[2*i]   for i in range(N_)] ; f1 = [f[2*i+1] for i in range(N_)] 
            ff0 = _ntt_(xi2,N_,f0) ; ff1 = _ntt_(xi2,N_,f1)  
    
            s  = xi ; ff = [self.F(0) for i in range(N)] 
            for i in range(N_):
                a = ff0[i] ; b = s*ff1[i]  
                ff[i] = a + b ; ff[i + N_] = a - b 
                s = s * xi2                     
            return ff 
        
        return _ntt_(self.xi,self.n,_expand_(f))
        
    def ntt_inv(self,ff):                 
        return sum([ff[i]*self.base[i] for i in range(self.n)])
    
    def random_pol(self,args=None):
        return (self.R).random_element(args)

# Funcoes auxiliares

# Soma de vetores
def sumVector(ff1, ff2, n):
    res = []
    for i in range(n):
        res.append((ff1[i] + ff2[i]))
    return res

# Soma de matrizes
def sumMatrix(e1, e2, n):
    for i in range(len(e1)):
        e1[i] = sumVector(e1[i], e2[i], n)
    return e1

# Multiplicação de vetores
def multVector(ff1, ff2, n):
    res = []
    # print(len(ff1))
    # print(len(ff2))
    for i in range(n):
        ff = ff1[i] * ff2[i]
        print(ff)
        res.append((ff1[i] * ff2[i]))
    return res

# Multiplicação de uma matriz por um vector
def multMatrixVector(M, v, k, n) :
    for i in range(len(M)):
        for j in range(len(M[i])):
            M[i][j] = multVector(M[i][j], v[j], n)
    tmp = [[0] * n] * k 
    for i in range(len(M)):
        for j in range(len(M[i])):
            tmp[i] = sumVector(tmp[i], M[i][j],n)
    return tmp

# Multiplicação de matrizes
def multMatrix(vec1, vec2, n):
    for i in range(len(vec1)):
        vec1[i] = multVector(vec1[i], vec2[i],n)
    tmp = [0] * n
    for i in range(len(vec1)):
        tmp = sumVector(tmp, vec1[i], n)
    return tmp

# Subtração de vetores
def subVector(ff1, ff2, n):
    res = []
    for i in range(n):
        res.append((ff1[i] - ff2[i]))
    return res

class Kyber:
    def __init__(self, parameter_set):
        self.n = parameter_set["n"]
        self.k = parameter_set["k"]
        self.q = parameter_set["q"]
        self.eta_1 = parameter_set["eta_1"]
        self.eta_2 = parameter_set["eta_2"]
        self.du = parameter_set["du"]
        self.dv = parameter_set["dv"]
        self.T = NTT(self.n,self.q)

        Zq.<w> = GF(self.q)[]
        fi = w^self.n + 1
        Rq.<w> = QuotientRing(Zq, Zq.ideal(fi))
        self.Rq = Rq
    
    # Pseudorandom function (PRF). The function PRF takes a parameter n ∈ {2,3}, one 32-byte input, and one 1-byte input. It produces one (64.n)-byte output
    def PRF(self,b,b1): 
        digest = hashes.Hash(hashes.SHAKE256(int(self.q)))
        digest.update(b + bytes([b1]))
        return digest.finalize()

    # eXtendable-output function (XOF). The function XOFtakes one 32-byte input and two 1-byte inputs. It produces a variable-length output
    def XOF(self,b,b1,b2):
        digest = hashes.Hash(hashes.SHAKE128(int(self.q)))
        digest.update(b + bytes([b1]) + bytes([b2]))
        m = digest.finalize()
        return m
    
    # Three Hash functions
    def H(self, s):
        digest = hashes.Hash(hashes.SHA3_256())
        digest.update(bytes(s))
        h = digest.finalize()
        return h

    # size should be 32
    def J(self, s, size=32):
        digest = hashes.Hash(hashes.SHAKE256(int(size)))
        digest.update(bytes(s))
        j = digest.finalize()
        return j

    def G(self, c):
        digest = hashes.Hash(hashes.SHA3_512())
        digest.update(c)
        g = digest.finalize()
        return g[:32], g[32:]
    
    # Converts a bit array into a byte array.
    def bits2Bytes(self, bitArray):
        # Length check
        if len(bitArray) % 8 != 0:
            raise ValueError("Input bit array length must be a multiple of 8")
        # Initialize byte array with zeros
        byteArray = [0] * (len(bitArray) // 8)
        # Convert bits to bytes
        for i in range(len(bitArray)):
            byte_index = i // 8  # Integer division for byte index
            bit_offset = i % 8  # Remainder for bit position within the byte
            byteArray[byte_index] += bitArray[i] << bit_offset  # Add bit value considering position
        return bytes(byteArray)

    def bytes2Bits(self, byteArray):
        bitArray = []
        for elem in byteArray:
            bitElemArr = []
            for i in range(0,8): 
                bitElemArr.append(Mod(elem//2**(Mod(i,8)),2))
                for i in range(0,len(bitElemArr)):
                    bitArray.append(bitElemArr[i])
        return bitArray

    def Compress(self,x,d) :
        coefficients = x.list()
        newCoefficients = []
        _2d = int(2 ** d)
        for c in coefficients:
            new = Mod(round((_2d / self.q) * int(c)), _2d)
            newCoefficients.append(new)
        return self.Rq(newCoefficients)
    
    def Decompress(self,x,d) :
        coefficients = x.list()
        newCoefficients = []
        _2d = 2 ** d
        for c in coefficients:
            new = round((self.q / _2d) * int(c))
            newCoefficients.append(new)
        return self.Rq(newCoefficients)

    def ByteEncode(self, f, l):
        byteArray = []
        bitArray = []
        for i in range(len(f)):
            for j in range(l):
                bitArray.append(Mod(f[i]//2**j,2))
        byteArray = self.bits2Bytes(bitArray)
        return byteArray

    def ByteDecode(self, byteArray, l):
        f = []
        bitArray = self.bytes2Bits(byteArray)
        for i in range(len(byteArray)):
            fi = 0
            for j in range(l):
                fi += int(bitArray[i*l+j]) * 2**j
            f.append(fi)
        return self.Rq(f)

    def SampleNTT(self, byteArray):
        i = 0
        j = 0
        a = []
        while j < self.n:
            d1 = byteArray[i] + 256 * Mod(byteArray[i+1],16)
            d2 = byteArray[i+1]//16 + 16 * byteArray[i+2]
            if d1 < self.q :
                a.append(d1)
                j = j+1
            if d2 < self.q and j<self.n:
                a.append(d2)
                j = j+1
            i = i+3
        return self.Rq(a)

    def SamplePolyCBD(self, byteArray, nn):
        f=[0]*self.n
        bitArray = self.bytes2Bits(byteArray)
        for i in range(self.n):
            x = 0
            y = 0
            for j in range(nn):
                x += bitArray[2*i*nn + j]
                y += bitArray[2*i*nn + nn + j]
            f[i] = x-y
        return self.Rq(f)

    def KPKE_keyGen(self):
        d = os.urandom(32)
        ro, sigma = self.G(d)
        N = 0
        
        # Generate matrix Â in Rq in NTT domain
        A = []
        for i in range(self.k):
            A.append([])
            for j in range(self.k):
                A[i].append(self.T.ntt(self.SampleNTT(self.XOF(ro,i,j))))
        
        # Sample s in Rq from Beta_1
        s = []  
        for i in range(self.k):
            s.insert(i,self.SamplePolyCBD(self.PRF(sigma,N), self.eta_1))
            N = N+1
            
        # Sample e in Rq from Beta_1
        e = []
        for i in range(self.k):
            e.insert(i,self.SamplePolyCBD(self.PRF(sigma,N), self.eta_1))
            N = N+1

        for i in range(self.k) :
            s[i] = self.T.ntt(s[i])
            e[i] = self.T.ntt(e[i])
            
        t = sumMatrix(multMatrixVector(A,s,self.k,self.n), e, self.n)
        
        ek = b"".join(self.ByteEncode(s, 12) for s in t) + ro
        dk = b"".join(self.ByteEncode(s, 12) for s in t)
        
        return ek, dk

    def KPKE_encrypt(self, ek, m, r):
        N = 0
        t = [self.ByteEncode(ek[i*128*self.k:(i+1)*128*self.k], 12) for i in range(self.k)]
        ro = ek[-32:]
        # Generate matrix Â in Rq in NTT domain
        transposeA = []
        for i in range(self.k):
            transposeA.append([])
            for j in range(self.k):
                transposeA[i].append(self.T.ntt(self.SampleNTT(self.XOF(ro,i,j))))
        
        # Sample r in Rq from Beta_1
        rr = []
        for i in range(self.k):
            rr.insert(i,self.T.ntt(self.SamplePolyCBD(self.PRF(r, N), self.eta_1)))
            N += 1
        
        # Sample e1 in Rq from Beta_2
        e1 = []
        for i in range(self.k):
            e1.insert(i,self.SamplePolyCBD(self.PRF(r, N), self.eta_2))
            N += 1
        
        # Sample e2 in Rq from Beta_2
        e2 = self.SamplePolyCBD(self.PRF(r, N), self.eta_2)
        
        uAux = multMatrixVector(transposeA, rr, self.k, self.n)
        uAux2 = []
        for i in range(len(uAux)) :
            uAux2.append(self.T.ntt_inv(uAux[i]))
        uAux3 = sumMatrix(uAux2, e1, self.n)
        u = []
        for i in range(len(uAux3)) :
            u.append(self.Rq(uAux3[i]))

        vAux = multMatrix(t, rr, self.n)
        vAux1 = self.T.ntt_inv(vAux)
        vAux2 = self.Rq(sumVector(vAux1, e2, self.n))
        
        v = self.Rq(sumVector(vAux2, self.Decompress(self.ByteDecode(m,1), 1), self.n))
        
        c1 = b"".join(self.ByteEncode(list(self.Compress(u[i], self.du)), self.du) for i in range(self.k))
        
        c2 = self.ByteEncode(list(self.Compress(v, self.dv)), self.dv)
        
        return c1 + c2

    def KPKE_decrypt(self, dk, c):
        c1 = c[:32*self.du*self.k]
        c2 = c[32*self.du*self.k:]
        u = []       
        for i in range(self.k):
            u.append(self.Decompress(self.ByteDecode(c1[i*32*self.du:(i+1)*32*self.du], self.du), self.du))
        
        v = self.Decompress(self.ByteDecode(c2, self.dv),self.dv)

        s = []
        for i in range(self.k):
                s.append(self.ByteDecode(dk[i*384:(i+1)*384], 12))
        #s = self.ByteDecode(dk, 12)
        
        uNTT = []
        for i in range(len(u)) :
            uNTT.append(self.T.ntt(u[i]))
        
        mAux = subVector(v, self.T.ntt_inv(multMatrix(s, uNTT, self.n)), self.n)

        m = self.ByteEncode(list(self.Compress(self.Rq(mAux), 1)), 1)
        
        return m

    ## ML-KEM

    def MLKEM_keygen(self):
        z = bytearray(os.urandom(32))
        ek, dk = self.KPKE_keyGen()
        ek = ek
        dk = (dk, ek, self.H(ek), z)
        return (ek,dk)

    def MLKEM_encaps(self, ek):
        m = os.urandom(32)
        K, r = self.G(m + self.H(ek))
        c = self.KPKE_encrypt(ek,m,r)
        return (K,c)
    
    def MLKEM_decaps(self, c, dk):
        dk = dk[:384*self.k]
        ek = dk[384*self.k : 768 * self.k + 32]
        h = dk[768*self.k + 32 : 768*self.k + 64]
        z = dk[768*self.k + 64 : 768*self.k + 96]
        m_ = self.KPKE_decrypt(dk,c)
        K_, r_ = self.G(m_ + h)
        K = self.J(z + c)
        c_ = self.KPKE_encrypt(ek,m_,r_)
        if c != c_:
            K_ = K
        return K_ 


## TESTE

kyber = Kyber(DEFAULT_PARAMETERS["kyber_512"])

ek, dk = kyber.MLKEM_keygen()

K, c = kyber.MLKEM_encaps(ek)
print("\nSecret key:")
print(K)
print("\nCiphertext:")
print(c)

plaintext = kyber.MLKEM_decaps(c, K)
print("\nDecrypted ciphertext:")
print(plaintext)