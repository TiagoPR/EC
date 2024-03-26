import hashlib, os 
from pickle import dumps
from sage.all import *

class Ed(object):
    def __init__(self,p, a, d , ed = None):
        assert a != d and is_prime(p) and p > 3
        K = GF(p) 
  
        A =  2*(a + d)/(a - d)
        B =  4/(a - d)
    
        alfa = A/(3*B) ; s = B

        a4 =  s**(-2) - 3*alfa**2
        a6 =  -alfa**3 - a4*alfa
        
        self.K = K
        self.constants = {'a': a , 'd': d , 'A':A , 'B':B , 'alfa':alfa , 's':s , 'a4':a4 , 'a6':a6 }
        self.EC = EllipticCurve(K,[a4,a6]) 
        
        if ed != None:
            self.L = ed['L']
            self.P = self.ed2ec(ed['Px'],ed['Py'])  # gerador do gru
        else:
            self.gen()
    
    def order(self):
        # A ordem prima "n" do maior subgrupo da curva, e o respetivo cofator "h" 
        oo = self.EC.order()
        n,_ = list(factor(oo))[-1]
        return (n,oo//n)
    
    def gen(self):
        L, h = self.order()       
        P = O = self.EC(0)
        while L*P == O:
            P = self.EC.random_element()
        self.P = h*P ; self.L = L
    
    def is_edwards(self, x, y):
        a = self.constants['a'] ; d = self.constants['d']
        x2 = x**2 ; y2 = y**2
        return a*x2 + y2 == 1 + d*x2*y2

    def ed2ec(self,x,y):      ## mapeia Ed --> EC
        if (x,y) == (0,1):
            return self.EC(0)
        z = (1+y)/(1-y) ; w = z/x
        alfa = self.constants['alfa']; s = self.constants['s']
        return self.EC(z/s + alfa , w/s)
    
    def ec2ed(self,P):        ## mapeia EC --> Ed
        if P == self.EC(0):
            return (0,1)
        x,y = P.xy()
        alfa = self.constants['alfa']; s = self.constants['s']
        u = s*(x - alfa) ; v = s*y
        return (u/v , (u-1)/(u+1))
    

class ed(object):
    def __init__(self,pt=None,curve=None,x=None,y=None):
        if pt != None:
            self.curve = pt.curve
            self.x = pt.x ; self.y = pt.y ; self.w = pt.w
        else:
            assert isinstance(curve,Ed) and curve.is_edwards(x,y)
            self.curve = curve
            self.x = x ; self.y = y ; self.w = x*y
    
    def eq(self,other):
        return self.x == other.x and self.y == other.y
    
    def copy(self):
        return ed(curve=self.curve, x=self.x, y=self.y)
    
    def zero(self):
        return ed(curve=self.curve,x=0,y=1)
    
    def sim(self):
        return ed(curve=self.curve, x= -self.x, y= self.y)
    
    def soma(self, other):
        a = self.curve.constants['a']; d = self.curve.constants['d']
        delta = d*self.w*other.w
        self.x, self.y  = (self.x*other.y + self.y*other.x)/(1+delta), (self.y*other.y - a*self.x*other.x)/(1-delta)
        self.w = self.x*self.y
        
    def duplica(self):
        a = self.curve.constants['a']; d = self.curve.constants['d']
        delta = d*(self.w)**2
        self.x, self.y = (2*self.w)/(1+delta) , (self.y**2 - a*self.x**2)/(1 - delta)
        self.w = self.x*self.y
        
    def mult(self, n):
        m = Mod(n,self.curve.L).lift().digits(2)   ## obter a representação binária do argumento "n"
        Q = self.copy() ; A = self.zero()
        for b in m:
            if b == 1:
                A.soma(Q)
            Q.duplica()
        return A
    
class EdDSA:
    storage = []
    
    def __init__(self, ed):
        if(ed=='ed25519'):
            print('Escolhida a curva Ed25519.')
            self.setup_ed25519()
        else:
            print('Escolhida a curva Ed448.')
            self.setup_ed448()

    def setup_ed25519(self):
        p = 2**255-19    
        K = GF(p)   
        a = K(-1)
        d = -K(121665)/K(121666)
        #

        ed25519 = {
        'b'  : 256,
        'Px' : K(15112221349535400772501151409588531511454012693041857206046113283949847762202),
        'Py' : K(46316835694926478169428394003475163141307993866256225615783033603165251855960),
        'L'  : ZZ(2**252 + 27742317777372353535851937790883648493), ## ordem do subgrupo primo
        'n'  : 254,
        'h'  : 8
        }

        Px = ed25519['Px']; Py = ed25519['Py']

        E = Ed(p,a,d,ed=ed25519)
        G = ed(curve=E,x=Px,y=Py)
        l = E.order()[0]

        self.b = ed25519['b']
        self.requested_security_strength = 128
        self.E = E
        self.G = G
        self.l = l
        self.algorithm = 'ed25519'

# hash function for each curve ED2556 and ED448
    def hash(self,data):
        if self.algorithm == 'ed25519':
            return hashlib.sha512(data).digest()
        else:
            return hashlib.shake_256(data).digest(912//8)

    # private key digest
    def digest(self,d):
        h = self.hash(d)
        buffer = bytearray(h)
        return buffer

    def s_value(self,h):
        if self.algorithm == 'ed25519':
            return self.s_value_ed25519(h)
        else:
            return self.s_value_ed448(h)

    def s_value_ed25519(self,h):
        digest = int.from_bytes(h, 'little')
        bits = [int(digit) for digit in list(ZZ(digest).binary())]
        x = 512 - len(bits)
        while x != 0:
            bits = [0] + bits
            x = x-1

        bits[0] = bits[1] = bits[2] = 0
        bits[self.b-2] = 1
        bits[self.b-1] = 0

        bits = "".join(map(str, bits))

        s = int(bits[::-1], 2)
        return s

    # point encoding
    def encoding(self,Q, n):
        x, y = Q.x, Q.y
        self.storage.insert(n,(x,y))
        return x
    
    # point decoding
    def decoding(self,n):
        Q = self.storage[n]
        return Q
    
    # KeyGen
    def keyGen(self):
        # private key
        d = os.urandom(self.b//8)
        # s value
        digest = self.digest(d) 
        if self.algorithm == 'ed25519':
            bytes_length = 32
        else:
            bytes_length = 57

        hdigest1 = digest[:bytes_length]
        s = self.s_value(hdigest1)
        
        # public key
        T = self.G.mult(s)

        # public key encoding
        Q = self.encoding(T,0)
        Q = int(Q).to_bytes(bytes_length, 'little')
        return d, Q

    # domain separation tag
    def dom4(self, f, context): 
        init_string = []
        context_octets = []
        
        for c in context:
            context_octets.append(format(ord(c), "08b"))
        context_octets = ''.join(context_octets)

        for c in "SigEd448":
            init_string.append(format(ord(c), "08b"))
        init_string = ''.join(init_string)

        bits_int = int(init_string + format(f, "08b") + format(len(context_octets), "08b") + context_octets, 2)
        byte_array = bits_int.to_bytes((bits_int.bit_length() + 7) // 8, 'little')
        
        return byte_array
        
    # Sign
    def sign(self,M,d,Q,context = ''):
        # private key hash
        digest = self.digest(d)

        if self.algorithm == 'ed25519':
            bytes_length = 32
            hashPK = digest[bytes_length:]
            hashPK_old = digest[:bytes_length]
            r = self.hash(hashPK+M)
        else:
            bytes_length = 57
            hashPK = digest[bytes_length:]
            hashPK_old = digest[:bytes_length]
            r = self.hash(self.dom4(0, context)+hashPK+M)
        
        # r value
        r = int.from_bytes(r, 'little')

        # calculate R and encoding it
        R = self.G.mult(r)
        Rx = self.encoding(R,1)
        R = int(Rx).to_bytes(bytes_length, 'little')

        # s value
        s = self.s_value(hashPK_old)
        
        if self.algorithm == 'ed25519':
            # (R || Q || M) hash
            hashString = self.hash(R+Q+M)
        else:
            # (dom4(0,context) || R || Q || M) hash
            hashString = self.hash(self.dom4(0, context)+R+Q+M)

        hashString = int.from_bytes(hashString, 'little')

        # S = (r + SHA-512(R || Q || M) * s) mod n
        S = mod(r + hashString * s,self.l)
        S = int(S).to_bytes(bytes_length, 'little')

        signature = R + S
        return signature
    
    # Verify
    def verify(self,M,A,Q, context = ''):
        if self.algorithm == 'ed25519':
            bytes_length = 32
        else:
            bytes_length = 57

        # get R and S from signature A
        R = A[:bytes_length]
        S = A[bytes_length:]
        s = int.from_bytes(S, 'little')

        # decoding S, R and Q
        if (s >= 0 and s < self.l):
            (Rx, Ry) = self.decoding(1)
            (Qx, Qy) = self.decoding(0)
            if(Rx != None and Qx != None):
                res = True
            else: return False
        else: return False

        # t value
        if self.algorithm == 'ed25519':
            digest = self.hash(R+Q+M)
        else:
            digest = self.hash(self.dom4(0, context)+R+Q+M)
            
        t = int.from_bytes(digest, 'little')

        # get variables for verifying process
        value = 2**3
        R = int.from_bytes(R, 'little')
        Q = int.from_bytes(Q, 'little')
        R = ed(curve=self.E,x=Rx,y=Ry)
        Q = ed(curve=self.E,x=Qx,y=Qy)

        # get verification conditions: [2**c * S]G == [2**c]R + (2**c * t)Q
        cond1 = self.G.mult(value*s)
        cond2 = R.mult(value)
        cond3 = Q.mult(value*t)
        cond2.soma(cond3)

        # final verification
        return cond1.eq(cond2)
    


edDSA = EdDSA('ed25519')
signed_message = "Esta mensagem está assinada!"
unsigned_message = "Esta mensagem não está assinada..."
print("Mensagem a ser assinada: " + signed_message)
privateKey, publicKey = edDSA.keyGen()
print("\nSK: ")
print(privateKey)
print("PK: ")
print(publicKey)
print()
assinatura = edDSA.sign(dumps(signed_message), privateKey, publicKey)
print("Assinatura: ")
print(assinatura)
print()
print("Verificação da autenticação da mensagem assinada:")
if edDSA.verify(dumps(signed_message), assinatura, publicKey)==True:
    print("Mensagem autenticada!")
else:
    print("Mensagem não autenticada...")
    
print()
print("Verificação da autenticação da mensagem não assinada:")
if edDSA.verify(dumps(unsigned_message), assinatura, publicKey)==True:
    print("Mensagem autenticada!")
else:
    print("Mensagem não autenticada...")



