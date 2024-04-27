# Importação das bibliotecas necessárias

import os
from hashlib import shake_128, shake_256, sha256, sha512
from bitstring import BitArray
from random import choice
import ast


# Declaração dos pârametros
n = 256

q = next_prime(3*n)
while q % (2*n) != 1:
    q = next_prime(q+1)
    

# Declaração dos anéis necessários
_Z.<w> = ZZ[]
R.<w> = QuotientRing(_Z, _Z.ideal(w^n + 1))

_q.<w> = GF(q)[]
_Rq.<w> = QuotientRing(_q, _q.ideal(w^n + 1))

Rq = lambda x : _Rq(R(x))


# Implementação da Classe NTT (Number Theoretic Transform)
class NTT(object):
    def __init__(self, n=128, q=None):
        if not  n in [32,64,128,256,512,1024,2048]:
            raise ValueError("Argumento inválido",n)
        self.n = n  
        if not q:
            self.q = 1 + 2*n
            while True:
                if (self.q).is_prime():
                    break
                self.q += 2*n
        else:
            if q % (2*n) != 1:
                raise ValueError("O valor 'q' não verifica a condição NTT")
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


# Função que executa a função ntt_inv para todos os elementos de uma matriz ou de um array
def my_ntt_inv(f):
    if type(f[0]) is list:
        res = []
        for i in range(len(f)):
            
            if type(f[i][0]) is list:
                res.append([])
                for j in range(len(f[i])):
                    res[i].append(T.ntt_inv(f[i][j]))
                    
            else:
                res.append(T.ntt_inv(f[i]))
    else:
        res = T.ntt_inv(f)
                
    return res


# Função que executa o ntt para todos os elementos de uma matriz ou de um array
def my_ntt(f):
    
    if type(f) is list:
        res = []
        for i in range(len(f)):
            
            if type(f[i]) is list:
                res.append([])
                for j in range(len(f[i])):
                    res[i].append(T.ntt(f[i][j]))
                    
            else:
                res.append(T.ntt(f[i]))
    else:
        res = T.ntt(f)
                
    return res


# Função que realiza a multiplicação entre dois objetos ntt
def my_mult(ff1, ff2, N=n, Q=q):
    res = []
    
    for i in range(N):
        res.append((ff1[i] * ff2[i]) % Q)

    return res


# Função que realiza a soma de dois objetos ntt
def my_add(ff1, ff2, N=n, Q=q):
    res = []

    for i in range(N):
        res.append((ff1[i] + ff2[i]) % Q)

    return res


# Função que realiza a subtração de dois objetos ntt
def my_sub(ff1, ff2, N=n, Q=q):
    res = []

    for i in range(N):
        res.append((ff1[i] - ff2[i]) % Q)

    return res


# Função compress, seguindo o algoritmo da documentação
def compress(x, d, q):
    coefs = x.list()
    
    new_coefs = []
    _2power = int(2 ** d)
    
    for coef in coefs:
        new_coef = round(_2power / q * int(coef)) % _2power
        new_coefs.append(new_coef)
        
    return Rq(new_coefs)
  

# Função compress aplicada a todos os elementos de uma matriz ou de um array    
def compress_rec(f, d, q):
    if type(f) is list:
        res = []
        for i in range(len(f)):
            if type(f[i]) is list:
                res.append([])
                for j in range(len(f[i])):
                    res[i].append(compress(f[i][j], d, q))
                    
            else:
                res.append(compress(f[i], d, q))
    else:
        res = compress(f, d, q)
                
    return res
 

# Função decompress, seguindo o algoritmo da documentação
def decompress(x, d, q):
    coefs = x.list()
    
    new_coefs = []
    _2power = 2 ** d
    
    for coef in coefs:
        new_coef = round(q / _2power * int(coef))
        new_coefs.append(new_coef)
        
    return Rq(new_coefs)


# Função decompress aplicada a todos os elementos de uma matriz ou de um array
def decompress_rec(f, d, q):
    if type(f) is list:
        res = []
        for i in range(len(f)):
            if type(f[i]) is list:
                res.append([])
                for j in range(len(f[i])):
                    res[i].append(decompress(f[i][j], d, q))
                    
            else:
                res.append(decompress(f[i], d, q))
    else:
        res = decompress(f, d, q)
                
    return res


# Inicialização de um objeto ntt
T = NTT(n=n, q=q)


# Função que efetua xor entre duas strings binárias
def xoring(key, text):
    # Se o text for maior do que a key, então a key é multiplicada as vezes que forem precisas
    if len(text) > len(key):
        t1 = len(text) / len(key)
        key *= ceil(t1)
    
    # Retorna o XOR
    return bytes(a ^^ b for a, b in zip(key, text))


# Instanciação de funções, seguindo a documentação
def XOF(p,i,j):
    return shake_128(str(i).encode() + str(j).encode() + str(p).encode()).digest(int(2000))

def H(s):
    return sha256(str(s).encode()).digest()

def G(a,b=""):
    digest = sha512(str(a).encode() + str(b).encode() ).digest()
    return digest[:32], digest[32:]

def PRF(s,b):
    return shake_256(str(s).encode() + str(b).encode()).digest(int(2000))

def KDF(a,b=""):
    return shake_256(str(a).encode() + str(b).encode()).digest(int(2000))


# Função parse, seguindo a documentação
def parse(b, q, n):
    i = 0
    j = 0
    a = []
    
    while j < n and i + 2 < len(b):
        d1 = b[i] + 256 * b[i + 1] % 16
        d2 = b[i+1]//16 + 16 * b[i + 2]
        
        if d1 < q:
            a.append(d1)
            j += 1
        
        elif d2 < q and j < n:
            a.append(d2)
            j += 1
        
        i += 3
    
    return Rq(a)


# Função Centered Binomial Distribution, seguindo a documentação
def CBD(byte_array, base):
    f = []
    
    bit_array = BitArray(bytes=byte_array).bin[2:]
    for i in range(256):
        a = 0
        b = 0
        
        for j in range(base):
            a += 2**j if int(bit_array[2*i * base + j]) else 0
            b += 2**j if int(bit_array[2*i * base + base + j]) else 0
        
        f.append(a-b)
    
    return R(f)


# Função que realiza a multiplicação entre uma matriz e um vetor, ambos objetos ntt
def mult_mat_vec(mat, vec, k=2, n=n):
    for i in range(len(mat)):
        for j in range(len(mat[i])):
            mat[i][j] = my_mult(mat[i][j], vec[j])
    
    tmp = [[0] * n] * k 
    for i in range(len(mat)):
        for j in range(len(mat[i])):
            tmp[i] = my_add(tmp[i], mat[i][j])
    
    return tmp


# Função que realiza a multiplicação entre dois vetores, ambos objetos ntt
def mult_vec(vec1, vec2, n=n):
    for i in range(len(vec1)):
        vec1[i] = my_mult(vec1[i], vec2[i])
    
    tmp = [0] * n
    for i in range(len(vec1)):
        tmp = my_add(tmp, vec1[i])
            
    return tmp


# Função que realiza a soma entre dois vetores, ambos os objetos ntt
def sum_vec(vec1, vec2):
    for i in range(len(vec1)):
        vec1[i] = my_add(vec1[i], vec2[i])
            
    return vec1

# Função que realiza a subtração entre dois vetores, ambos os objetos ntt
def sub_vec(vec1, vec2):
    for i in range(len(vec1)):
        vec1[i] = my_sub(vec1[i], vec2[i])
            
    return vec1

# Classe que implementa o KEM IND-CPA seguro
class Kyber:
    def __init__(self, n, k, q, n1, n2, du, dv):
        self.n = n
        self.k = k
        self.q = q
        self.n1 = n1
        self.n2 = n2
        self.du = du
        self.dv = dv
    
    
    # Função que gera a chave, seguindo a documentação
    def keygen(self):
        d = _Rq.random_element()
        p, o = G(d)
        
        N = 0
        
        # Inicializa a matriz
        A = [0, 0]
        # Gera a matriz A
        for i in range(self.k):
            A[i] = []
            for j in range(self.k):
                A[i].append(T.ntt(parse(XOF(p, j, i), self.q, self.n)))
        
        # Gera o array "s" e  o "e"
        s = [0] * self.k
        for i in range(self.k):
            s[i] = T.ntt(CBD(PRF(o, N), self.n1))
            N += 1
        
        e = [0] * self.k
        for i in range(self.k):
            e[i] = T.ntt(CBD(PRF(o, N), self.n1))
            N += 1
        
        mult = mult_mat_vec(A, s)
        t = sum_vec(mult, e)
        
        self.pk = t, p
        self.sk = s
        
        return self.sk, self.pk
    
    
    # Função para cifrar, seguindo a documentação
    def encrypt(self, pk, m, coins):
        N = 0
        t, p = pk
        
        # Inicializa a matriz
        A = [0, 0]
        # Gera a matriz A
        for i in range(self.k):
            A[i] = []
            for j in range(self.k):
                A[i].append(T.ntt(parse(XOF(p, i, j), self.q, self.n)))
        
         # Gera o array "r" e  o "e1"
        r = [0] * self.k
        for i in range(self.k):
            r[i] = T.ntt(CBD(PRF(coins, N), self.n1))
            N += 1

        e1 = [0] * self.k
        for i in range(self.k):
            e1[i] = T.ntt(CBD(PRF(coins, N), self.n2))
            N += 1
        
        e2 = T.ntt(CBD(PRF(coins, N), self.n2))
        
        mult = mult_mat_vec(A, r)
        u = sum_vec(mult, e1)
 
        t = [] + t
        mult = mult_vec(t, r)
        v = my_add(mult, e2)
        v = my_add(v, T.ntt(m))
        
        u = my_ntt_inv(u)
        v = my_ntt_inv(v)
        
        c1 = compress_rec(u, self.du, self.q)
        c2 = compress_rec(v, self.dv, self.q)
        
        return (c1, c2)
    
    
    # Função para decifrar, seguindo a documentação
    def decrypt(self, c):
        u, v = c
        u = decompress_rec(u, self.du, q)
        v = decompress_rec(v, self.dv, q)

        u = my_ntt(u)
        v = my_ntt(v)
        
        s = [] + self.sk
        
        mult = mult_vec(s, u)
        m = my_sub(v, mult)
        
        return compress(T.ntt_inv(m), 1, q)
 
    
    # Função para o encapsulamento
    def encaps(self, pk):
        # Gera o polinómio para o encapsulamento
        m1 = Rq([choice([0, 1]) for i in range(n)])
        coins = os.urandom(256)
        
        # Obtem o criptograma
        e = self.encrypt(pk, decompress(m1, 1, q), coins)
        # Obtem a chave partilhada
        k = H(m1)

        return e, k
    
    # Função para o desencapsulamento
    def decaps(self, c):
        
        # Obtem polinómio gerado no encapsulamento
        m = self.decrypt(c)
        
        # Obtem a chave partilhada
        k = H(m)
        
        return k
    
    
    # Função para cifrar com o KEM
    def encrypt_kem(self, pk, m):
        # Obtem o criptograma da chave partilhada e a chave partilhada
        e, k = self.encaps(pk)
        
        # Obtem o criptograma
        c = xoring(k, m.encode('utf-8'))
        
        return e, c
    
    # Função para decifrar com o KEM
    def decrypt_kem(self, e, c):
        # Obtem chave partilhada
        k = self.decaps(e)
        
        # Obtem a mensagem
        m = xoring(k, c).decode('utf-8')
        
        return m
    
# Cria uma instância da classe Kyber
kyber = Kyber(n, 2, q, 3, 2, 10, 4)

# Gera um par de chaves
sk, pk = kyber.keygen()

# Encapsulamento: gera o criptograma e a chave partilhada
e1, k_encaps = kyber.encaps(pk)

# Cifra a mensagem
e, c = kyber.encrypt_kem(pk, "Unidade Curricular de Estruturas Criptográficas")

# Desencapsulamento: obtem a chave partilhada do criptograma
k_decaps = kyber.decaps(e1)

#Verifica se as chaves obtidas são iguais
if k_encaps == k_decaps:
    print("As chaves partilhadas são iguais.")
else:
    print("erro")

# Decifra a mensagem
m = kyber.decrypt_kem(e, c)

if m == "Unidade Curricular de Estruturas Criptográficas":
    print("Cifragem e decifragem bem sucedida!!")
else:
    print("erro")

print("Mensagem original:", "Unidade Curricular de Estruturas Criptográficas")
print("Mensagem decifrada:", m)
print()
print(e1)

# Classe que implementa o PKE-IND-CCA seguro
class Kyber_CCA:
    def __init__(self, n, k, q, n1, n2, du, dv):
        self.n = n
        self.k = k
        self.q = q
        self.n1 = n1
        self.n2 = n2
        self.du = du
        self.dv = dv
        
        self.kyber = Kyber(n, k, q, n1, n2, du, dv)
    
    # Função para gerar a chave, usando a função keygen da classe anterior
    def keygen(self):    
        self.sk, self.pk = self.kyber.keygen()
        
        return self.sk, self.pk
    
    
    # Função para cifrar, usando a função encrypt da classe anterior
    def encrypt(self, pk, r, y):
        # Obtem a hash r||y
        ry = H(bytes(r) + y)
        
        # Cifra r e a hash r||y
        c = self.kyber.encrypt(pk, decompress(r, 1, self.q), ry)
        
        return c
    
    
    # Função para decifrar, usando a função decrypt da classe anterior
    def decrypt(self, c):
        r = self.kyber.decrypt(c)
        
        return r
    
    # Função para cifrar com a transformação Fujisaki-Okamoto
    def encrypt_fo(self, m, pk):
        r = Rq([choice([0, 1]) for i in range(n)])
        
        g = H(r)
        
        y = xoring(g, bytes(m, encoding='utf-8'))
        
        c = self.encrypt(pk, r, y)
        
        return y, c
    
    # Função para decifrar com a transformação Fujisaki-Okamoto
    def decrypt_fo(self, y, c):
        r = self.decrypt(c)
        
        _c = self.encrypt(pk, r, y)
        
        if c != _c:
            raise Exception("Mensagem não pode ser decifrada")
        
        g = H(r)
        
        m = xoring(g, y)
        
        return m.decode('utf-8')
    
# Cria uma instância da classe Kyber_CCA
kyber = Kyber_CCA(n, 2, q, 3, 2, 10, 4)

# Gera um par de chaves
sk, pk = kyber.keygen()

# Cifra a mensagem
y, c = kyber.encrypt_fo("Trabalho prático número 3", pk)

# Decifra a mensagem
m = kyber.decrypt_fo(y, c)

#Verifica se as mensagens são iguais
if m == "Trabalho prático número 3":
    print("Cifragem e decifragem bem sucedida!!")
else:
    print("erro")

print("Mensagem original:", "Trabalho prático número 3")
print("Mensagem decifrada:", m)