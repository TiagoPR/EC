from sage.all import *


lmbda = 256
q = random_prime(2**lmbda, proof=True, lbound=2**(lmbda-1))
print("q = ", q)

G = 2

identidade = b"identidade"

F = GF(q)
q2 = next_prime(q^2)
F2 = GF(q2)


def Zr(q):
    s = ZZ.random_element(1, q)  # Generate a random integer in Zq
    return s

def g(n):
    return ZZ(n * G)

def KeyGen(lmbda):
    # Generate a secret key s
    s = Zr(2**lmbda)  # Generate a random integer in Zq

    # Compute the public key beta
    beta = g(s)  # Compute s * G

    return s, beta

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

def KeyExtract(id):
    return s * id

def Xor(a,b):
    int_a = int(a)
    int_b = int(b)
    return int_a ^ int_b

# Curvas Elipticas supersingulares em Sagemath
# a curva supersingular sobre Fp2  definida pela equação  y^2 = x^3 + 1
E2 = EllipticCurve(F2, [0,1])

def phi(P):             # a isogenia que mapeia  (x,y)  ->  (z*x,y)
    (x,y) = P.xy()
    return E2(lmbda*x,y)

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

s, beta = KeyGen(lmbda)
print("s=", s, " beta=", beta)

d = ID(identidade)
print("d = ", d)
key = KeyExtract(d)
print("key = ", key)
mensagem = 1234
c = Encrypt(d, mensagem)

x = Decrypt(key, c)
print("x = ", x)

