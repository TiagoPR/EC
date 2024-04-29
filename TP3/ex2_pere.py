from cryptography.hazmat.primitives import hashes
from pickle import dumps, loads
# Classe que implementa as multiplicações em R - number-theoretic transform (NTT) 
class NTT:

    def __init__(self, n=128, q=None):
        
        if not  n in [32,64,128,256,512,1024,2048]:
            raise ValueError("improper argument ",n)
        self.n = n  
        if not q:
            self.q = 1 + 2*n
            while True:
                if (self.q).is_prime():
                    break
                self.q += 2*n
        else:
            if q % (2*n) != 1:
                raise ValueError("Valor de 'q' não verifica a condição NTT")
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
        
    def invNtt(self,ff):                             
        return sum([ff[i]*self.base[i] for i in range(self.n)])
    
# Operações sobre matrizes e vetores
# Soma de matrizes
def sumMatrix(e1, e2, n):
    for i in range(len(e1)):
        e1[i] = sumVector(e1[i], e2[i], n)
    return e1

# Subtração de matrizes
def subMatrix(e1, e2, n):
    for i in range(len(e1)):
        e1[i] = subVector(e1[i], e2[i], n)
    return e1

# Multiplicação de matrizes
def multMatrix(vec1, vec2, n):
    for i in range(len(vec1)):
        vec1[i] = multVector(vec1[i], vec2[i],n)
    tmp = [0] * n
    for i in range(len(vec1)):
        tmp = sumVector(tmp, vec1[i], n)
    return tmp

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

# Soma de vetores
def sumVector(ff1, ff2, n):
    res = []
    for i in range(n):
        res.append((ff1[i] + ff2[i]))
    return res

# Multiplicação de vetores
def multVector(ff1, ff2, n):
    res = []
    for i in range(n):
        res.append((ff1[i] * ff2[i]))
    return res

# Subtração de vetores
def subVector(ff1, ff2, n):
    res = []
    for i in range(n):
        res.append((ff1[i] - ff2[i]))
    return res

class KYBER_PKE:
    
    def __init__(self, pset):
        self.n, self.q, self.T, self.k, self.n1, self.n2, self.du, self.dv, self.Rq = self.setup(pset)
    
    def setup(self, pset):
        n = 256
        q = 7681
        n2 = 2
        if pset == 512:
            k = 2
            n1 = 3
            du = 10
            dv = 4
        elif pset == 768:
            k = 3
            n1 = 2
            du = 10
            dv = 4
        elif pset == 1024:
            k = 4
            n1 = 2
            du = 11
            dv = 5
        else: print("Error: Parameter set not valid!")
            
        Zq.<w> = GF(q)[]
        fi = w^n + 1
        Rq.<w> = QuotientRing(Zq, Zq.ideal(fi))
        
        T = NTT(n,q)
        
        return n, q, T, k, n1, n2, du, dv, Rq
    
    def bytes2Bits(self, byteArray):
        bitArray = []
        for elem in byteArray:
            bitElemArr = []
            for i in range(0,8): 
                bitElemArr.append(mod(elem//2**(mod(i,8)),2))
                for i in range(0,len(bitElemArr)):
                    bitArray.append(bitElemArr[i])
        return bitArray
    
    def G(self, h):
        digest = hashes.Hash(hashes.SHA3_512())
        digest.update(bytes(h))
        g = digest.finalize()
        return g[:32],g[32:]
    
    def XOF(self,b,b1,b2):
        digest = hashes.Hash(hashes.SHAKE128(int(self.q)))
        digest.update(b)
        digest.update(bytes(b1))
        digest.update(bytes(b2))
        m = digest.finalize()
        return m
    
    def PRF(self,b,b1): 
        digest = hashes.Hash(hashes.SHAKE256(int(self.q)))
        digest.update(b)
        digest.update(bytes(b1))
        return digest.finalize()

    def Compress(self,x,d) :
        coefficients = x.list()
        newCoefficients = []
        for c in coefficients:
            new = mod(round( int(2 ** d) / self.q * int(c)), int(2 ** d))
            newCoefficients.append(new)
        return self.Rq(newCoefficients)
    
    def Decompress(self,x,d) :
        coefficients = x.list()
        newCoefficients = []
        for c in coefficients:
            new = round(self.q / (2 ** d) * int(c))
            newCoefficients.append(new)
        return self.Rq(newCoefficients)
    
    # Método XOR
    def xor(self, b1, b2):
        return bytes(a ^^ b for a, b in zip(b1, b2))
    
    # Algorithm 1
    def Parse(self, byteArray):
        i = 0
        j = 0
        a = []
        while j < self.n:
            d1 = byteArray[i] + 256 * mod(byteArray[i+1],16)
            d2 = byteArray[i+1]//16 + 16 * byteArray[i+2]
            if d1 < self.q :
                a.append(d1)
                j = j+1
            if d2 < self.q and j<self.n:
                a.append(d2)
                j = j+1
            i = i+3
        return self.Rq(a)
    
    
    # Algorithm 2
    def CBD(self, byteArray, nn):
        f=[0]*self.n
        bitArray = self.bytes2Bits(byteArray)
        for i in range(256):
            a = 0
            b = 0
            for j in range(nn):
                a += bitArray[2*i*nn + j]
                b += bitArray[2*i*nn + nn + j]
            f[i] = a-b
        return self.Rq(f)
    
    # Algorithm 3
    def Decode(self, byteArray, l):
        f = []
        bitArray = self.bytes2Bits(byteArray)
        for i in range(len(byteArray)):
            fi = 0
            for j in range(l):
                fi += int(bitArray[i*l+j]) * 2**j
            f.append(fi)
        return self.Rq(f)
    
    # Algorithm 4
    def keyGen(self):
        d = bytearray(os.urandom(32))
        ro, sigma = self.G(d)
        N = 0
        
        # Generate matrix Â in Rq in NTT domain
        A = []
        for i in range(self.k):
            A.append([])
            for j in range(self.k):
                A[i].append(self.T.ntt(self.Parse(self.XOF(ro,j,i))))
        
        # Sample s in Rq from Bη1
        s = []  
        for i in range(self.k):
            s.insert(i,self.CBD(self.PRF(sigma,N), self.n1))
            N = N+1
            
        # Sample e in Rq from Bη1
        e = []
        for i in range(self.k):
            e.insert(i,self.CBD(self.PRF(sigma,N), self.n1))
            N = N+1

        for i in range(self.k) :
            s[i] = self.T.ntt(s[i])
            e[i] = self.T.ntt(e[i])
            
        t = sumMatrix(multMatrixVector(A,s,self.k,self.n), e, self.n)
        
        pk = t, ro
        sk = s
        
        return pk, sk
    
    # Algorithm 5
    def encrypt(self, pk, m, r):
        N = 0
        t, ro = pk
        
        # Generate matrix Â in Rq in NTT domain
        transposeA = []
        for i in range(self.k):
            transposeA.append([])
            for j in range(self.k):
                transposeA[i].append(self.T.ntt(self.Parse(self.XOF(ro,i,j))))
        
        # Sample r in Rq from Bη1
        rr = []
        for i in range(self.k):
            rr.insert(i,self.T.ntt(self.CBD(self.PRF(r, N), self.n1)))
            N += 1
        
        # Sample e1 in Rq from Bη2
        e1 = []
        for i in range(self.k):
            e1.insert(i,self.CBD(self.PRF(r, N), self.n2))
            N += 1
        
        # Sample e2 in Rq from Bη2
        e2 = self.CBD(self.PRF(r, N), self.n2)
        
        uAux = multMatrixVector(transposeA, rr, self.k, self.n)
        uAux2 = []
        for i in range(len(uAux)) :
            uAux2.append(self.T.invNtt(uAux[i]))
        uAux3 = sumMatrix(uAux2, e1, self.n)
        u = []
        for i in range(len(uAux3)) :
            u.append(self.Rq(uAux3[i]))
            
        vAux = multMatrix(t, rr, self.n)
        vAux1 = self.T.invNtt(vAux)
        vAux2 = self.Rq(sumVector(vAux1, e2, self.n))
        
        v = self.Rq(sumVector(vAux2, self.Decompress(m, 1), self.n))
        
        # Compress(u, du)
        c1 = []
        for i in range(len(u)):
            c1.append(self.Compress(u[i], self.du))
        
        # Compress(v, dv)
        c2 = self.Compress(v, self.dv)
        
        return c1, c2
    
    # Algorithm 6
    def decrypt(self, sk, c):
        c1, c2 = c
 
        u = []       
        for i in range(len(c1)):
            u.append(self.Decompress(c1[i], self.du))
        
        v = self.Decompress(c2,self.dv)

        s = sk
        
        uNTT = []
        for i in range(len(u)) :
            uNTT.append(self.T.ntt(u[i]))
        
        mAux = subVector(v, self.T.invNtt(multMatrix(s, uNTT, self.n)), self.n)

        m = self.Compress(self.Rq(mAux), 1)
        
        return m
    
    # hashes h e g
    # def hashFOT(self, b):
    #     r = hashes.Hash(hashes.SHA3_256())
    #     r.update(b)
    #     return r.finalize()
    
    def hashFOT(self, b):
        r = hashes.Hash(hashes.SHA3_256())
        for item in b:
            r.update(item)
        return r.finalize()


    def MLKEM_Keygen(self):
        z = os.urandom(32)
        (ek,dk_pke) = kyber.keyGen()
        dk = (dk_pke,ek,z) 
        return (ek,dk)

    def MLKEM_Encaps(self,ek):
        m = os.urandom(32)
        (K,r) = kyber.G(m)
        c = kyber.encrypt(ek,m,r)
        return (K,c)

    def MLKEM_Decaps(self,c,dk):
        (dk_pke, ek_pke, z) = dk
        m_ = kyber.decrypt(dk_pke,c)
        (K_,r_) = kyber.G(m_)
        c_ = kyber.encrypt(ek_pke,m_,r_)
        if c != c_ :
            print("reject")
        return K_
    
    def encryptCCA(self, x, pk):
        r = self.Rq([choice([0, 1]) for i in range(self.n)])
        y = self.xor(x, self.hashFOT(bytes(r)))
        c = self.encrypt(pk, r, self.hashFOT(bytes(r)+y))
        return (y, c)

    def decryptCCA(self, y, c, pk, sk):
        r = self.decrypt(sk, c)
        derived_c = self.encrypt(pk, r, self.hashFOT(bytes(r)+y))
        if c[0] != derived_c[0]:
            print("Error: key doesn't match!")
            return None
        else:
            return self.xor(y, self.hashFOT(bytes(r)))

kyber = KYBER_PKE(512)

ek, dk = kyber.MLKEM_Keygen()
m = b'Hello there!'
print("Original message:")
print(m)

K, c = kyber.MLKEM_Encaps(ek)
print("\nCiphertext:")
print(c)

plaintext = kyber.MLKEM_Decaps(c, d)
print("\nDecrypted ciphertext:")
print(plaintext)
