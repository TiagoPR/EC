
from sage.all import *

# Geração dos primos  q, p
bq     = 192                # tamanho em bits do primo "q"
bp     = 768                # tamanho minimo em bits do primo "p"

q = random_prime(2^bq-1,lbound=2^(bq-1))

t = q*3*2^(bp - bq)
while not is_prime(t-1):
    t = t << 1

p = t - 1

# Aneis e Corpos
Fp     = GF(p)                  # corpo primo com "p" elementos
R.<z>  = Fp[]                   # anel dos polinomios em "z" de coeficientes em Fp
f     = R(z^2 + z + 1)
Fp2.<z> = GF(p^2, modulus=f)   
# extensão de Fp de dimensão 2 cujo módulo é o polinómio "f"
# o polinómio "f"  é irredutivel, tem grau 2 e verifica  z^3 = 1 mod f
# se o ponto (x,y) verificar a equação y^2 = x^3 + 1, 
#      então o ponto (z*x,y) verifica a mesma equação

def trace(x):       # função linear que mapeia Fp2  em  Fp
    return x + x^p

# Curvas Elipticas supersingulares em Sagemath

# a curva supersingular sobre Fp2  definida pela equação  y^2 = x^3 + 1
E2 = EllipticCurve(Fp2, [0,1])

# ponto arbitrário  de ordem "q" em E2        
cofac = (p + 1)//q
G = cofac * E2.random_point()

# emparelhamento e oraculo DDHP

def phi(P):             # a isogenia que mapeia  (x,y)  ->  (z*x,y)
    (x,y) = P.xy()
    return E2(z*x,y)

def TateX(P,Q,l=1):      # o emparelhamento de Tate generalizado
    return P.tate_pairing(phi(Q), q, 2)^l

def ddhp(P,Q,R):        # o oraculo DDHP  que decide se (P,Q,R) é um triplo de DH
    return tateX(P,Q) == tateX(R,G)