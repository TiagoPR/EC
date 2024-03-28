from sage.all import *
from sage.schemes.elliptic_curves import *

# Geração dos primos  q, p
bq     = 160                # tamanho em bits do primo "q". Deve ser entre 160-bit e 512-bit
bp     = 512                # tamanho minimo em bits do primo "p". Deve ser entre 512-bit e 7680-bit

# q - A 160-bit to 512-bit prime that is the order of the cyclic subgroup of interest in E(F_p).
q = random_prime(2**bq-1,lbound=2**(bq-1))

# tem de se verificar p = 2^t * q * 3 - 1 iterativamente até encontrar um primo
t = q*3*2^(bp - bq)
while not is_prime(t-1):
    t = t << 1

p = t - 1

Fp = GF(p)          # corpo primo com "p" elementos
R.<z> = Fp[]        # anel dos polinomios em "z" de coeficientes em Fp
f = R(z^2 + z + 1)
Fp2.<z> = GF(p**2, modulus=f)
# extensão de Fp de dimensão 2 cujo módulo é o polinómio "f"
# o polinómio "f"  é irredutivel, tem grau 2 e verifica  z^3 = 1 mod f
# se o ponto (x,y) verificar a equação y^2 = x^3 + 1, 
#      então o ponto (z*x,y) verifica a mesma equação

# Função que mapeia Fp2 em Fp
def trace(x):       # função linear que mapeia Fp2  em  Fp
    return x + x^p

# Gerar as curvas $$E_1 \;\equiv\; E/\mathbb{F}_p\,$$ e  $$\;E_2\;\equiv\;E/\mathbb{F}_{p^2}\,$$ com a equação $$\,y^2 = x^3 + 1\,$$
E1 = EllipticCurve(Fp, [0,1])

# a curva supersingular sobre Fp  definida pela equação  y^2 = x^3 + a * x + b
E2 = EllipticCurve(Fp2, [0,1])

print(E2.is_supersingular())

# GrupoG = {n * Gerador | 0 < n < q}  # gerador de ordem "q" em E2
# Gerador = cofac * P
# cofac = (p + 1)//q

# ponto arbitrário  de ordem "q" em E2
P = E2.random_point() # E2.random_point() é um ponto arbitrário em E2
cofac = (p + 1)//q # cofactor de E2
G = cofac * P # gerador de ordem "q" em E2

# emparelhamento e oraculo DDHP

def phi(P):             # a isogenia que mapeia  (x,y)  ->  (z*x,y)
    (x,y) = P.xy()
    return E2(z*x,y)

def TateX(P,Q,l=1):      # o emparelhamento de Tate generalizado
    return P.tate_pairing(phi(Q), q, 2)^l

def ddhp(P,Q,R):        # o oraculo DDHP  que decide se (P,Q,R) é um triplo de DH
    return TateX(P,Q) == TateX(R,G)

def Zr(q):
    s = ZZ.random_element(1, q-1)  # Generate a random integer in Zq (0...q-1)
    return s

def g(n):
    return int(n) * G # Grupo de torção G de ordem q em E2

def KeyGen(q):
    # Generate a secret key s
    s = Zr(q)  # Generate a random integer in Zq (0...q-1)

    # Compute the public key beta
    beta = g(s)  # Compute s * G

    return s, beta

'''
# Corpo finito Fp^2 - Inteiro
def f(F2=F2):
    # devolve um inteiro
    return F2.random_element()

def h(bytes):
    int_val = int.from_bytes(bytes, "little")
    return int_val

def H(int):
    return int % q

def ID(identidade):
    return g(h(identidade))

def KeyExtract(s,id):
    return s * id

def Xor(a,b):
    int_a = int(a)
    int_b = int(b)
    return int_a ^ int_b

def phi(P):             # a isogenia que mapeia  (x,y)  ->  (z*x,y)
    (x,y) = P.xy()
    return E(bp*x,y)

def ex(beta,id,a):
    return beta.tate_pairing(phi(id), q, 2)^a

def input_E(id,x):
    v = Zr(id)
    a = H(Xor(v,x))
    u = ex(beta, id, a)
    return (x,v,a,u)

def output_E(x,v,a,u):
    alfa = g(a)
    v_ = Xor(v,f(u))
    x_ = Xor(x,H(v))
    return (alfa,v_,x_)

def Encrypt(id,x):
    (x,v,a,u) = input_E(id,x)
    (alfa, v_, x_) = output_E(x,v,a,u)
    # build criptograma from alfa, v_, x_
    criptograma = (alfa, v_, x_)
    return criptograma

def input_D(key, alfa, v_, x_):
    u = ex(alfa,key,1)
    v = Xor(v_, f(u))
    x = Xor(x_, H(v))
    return (alfa,v,x)

def output_D(alfa, v, x):
    a = H(Xor(v,x))
    if alfa != g(a):
        return None
    return x

def Decrypt(key, criptograma):
    (alfa, v_, x_) = criptograma
    (alfa,v,x) = input_D(key, alfa, v_, x_)
    x = output_D(alfa,v,x)
    if x is None:
        print("Decryption failed")
    return x
'''

s, beta = KeyGen(bp)
print("s=", s, " beta=", beta)

# d = ID(identidade)
# print("d = ", d)
# key = KeyExtract(s,d)
# print("key = ", key)
# mensagem = 1234
# c = Encrypt(d, mensagem)

# x = Decrypt(key, c)
# print("x = ", x)