from sage.all import *

class NTT(object):
    """
        Class representing the Number Theoretic Transform (NTT).

        The NTT class provides methods for performing the forward and inverse NTT on polynomials.

        Args:
            n (int): The size of the polynomial. Must be one of [32, 64, 128, 256, 512, 1024, 2048].
            q (int, optional): The modulus value. If not provided, a suitable value of q is chosen based on the rules of NTT.

        Raises:
            ValueError: If the value of n is not one of the allowed sizes.

        Attributes:
            n (int): The size of the polynomial.
            q (int): The modulus value.
            F (FiniteField): The finite field used for computations.
            R (PolynomialRing): The polynomial ring used for computations.
            xi (Element): The primitive root of unity.
            base (list): The Chinese Remainder Theorem (CRT) basis.

        Methods:
            ntt(f): Performs the forward NTT on the input polynomial f.
            ntt_inv(ff): Performs the inverse NTT on the input polynomial ff.
            random_pol(args): Generates a random polynomial.

        """
    def __init__(self, n=128, q=None):
        if not  n in [32,64,128,256,512,1024,2048]:
            raise ValueError("improper argument ",n)
        self.n = n

        # Se q não for fornecido, escolhe um valor de q de acordo com as regras do NTT
        if not q:
            self.q = 1 + 2*n
            while True:
                if (self.q).is_prime():
                    break
                self.q += 2*n
        else:
            # Se q for fornecido, verifica se satisfaz a condição NTT
            if q % (2*n) != 1:
                raise ValueError("Valor de 'q' não verifica a condição NTT")
            self.q = q
        
        # Define o campo finito e o anel de polinómios
        self.F = GF(self.q) ;  self.R = PolynomialRing(self.F, name="w")
        w = (self.R).gen()
        
        # Calcula a raiz primitiva da unidade xi
        g = (w**n + 1) # 
        xi = g.roots(multiplicities=False)[-1] # 
        self.xi = xi
        rs = [xi**(2*i+1)  for i in range(n)] 
        self.base = crt_basis([(w - r) for r in rs])  
    
    
    def ntt(self,f):
        def _expand_(f): 
            u = f.list()
            return u + [0]*(self.n-len(u)) 
        
        def _ntt_(xi,N,f):
            if N==1:
                return f
            N_ = N//2 ; xi2 =  xi**2  
            f0 = [f[2*i]   for i in range(N_)] ; f1 = [f[2*i+1] for i in range(N_)] 
            ff0 = _ntt_(xi2,N_,f0) ; ff1 = _ntt_(xi2,N_,f1)  
    
            s  = xi ; ff = [self.F(0) for i in range(N)] 
            for i in range(N_):
                a = ff0[i] ; b = s*ff1[i]  
                ff[i] = a + b ; ff[i + N_] = a - b 
                s = s * xi2                     
            return ff 
        
        return _ntt_(self.xi,self.n,_expand_(f))
        
    def ntt_inv(self,ff):                              ## transformada inversa
        return sum([ff[i]*self.base[i] for i in range(self.n)])
    
    def random_pol(self,args=None):
        return (self.R).random_element(args)
    
# Teste

#T = NTT(n=1024)
T = NTT(n=2048,q=343576577)

f = T.random_pol(1023)

ff = T.ntt(f)

fff = T.ntt_inv(ff)

# print(fff)
print("Correto ? ",f == fff)