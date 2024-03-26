from sage.all import *

#Decode a hexadecimal string representation of the integer.
def hexi(s): return int.from_bytes(bytes.fromhex(s),byteorder="big")

#A point on (twisted) Edwards curve.
class EdwardsPoint:
    def __init__(self,pt=None,curve=None,x=None,y=None):
        if pt is not None:
            self.curve=pt.curve
            w = pt.x*pt.y
            self.initpoint(pt.x,pt.y, w)
        else:
            self.curve=curve
            w = x*y
            self.initpoint(x,y, w)
    def initpoint(self, x, y, w):
        self.x=x
        self.y=y
        self.w=w

# A Class of twisted Edwards curve.
class EdwardsCurve:
     

     
class Edwards25519Point(EdwardsPoint):
    p = 2**255-19
    K = GF(p)
    a = K(-1)
    d = -K(121665) / K(121666)
    f0= K(0)
    f1= K(1)
    xb= K(hexi("216936D3CD6E53FEC0A4E231FDD6DC5C692CC76"+\
        "09525A7B2C9562D608F25D51A"))
    yb= K(hexi("666666666666666666666666666666666666666"+\
        "6666666666666666666666658"))
    
    @staticmethod
    def stdbase():
        return Edwards25519Point(Edwards25519Point.xb,\
            Edwards25519Point.yb)
    
    def __init__(self,x,y):
        #Check the point is actually on the curve.
        if y*y-x*x!=self.f1+self.d*x*x*y*y:
            raise ValueError("Invalid point")
        self.initpoint(x, y)
        self.w=x*y

    def decode(self, s):
        # Decode a point representation.
        x, y = self.decode_base(s, 256)
        return Edwards25519Point(x, y) if x is not None else None

    def encode(self):
        # Encode a point representation.
        return self.encode_base(256)



def decode_base(self,s,b):
        #Check that point encoding is the correct length.
        if len(s)!=b//8: return (None,None)
        #Extract signbit.
        s=bytearray(s)
        xs=s[(b-1)//8]>>((b-1)&7)
        #Decode y.  If this fails, fail.
        y = self.K.frombytes(s,b)
        if y is None: return (None,None)
        #Try to recover x.  If it does not exist, or if zero and xs
        #are wrong, fail.
        x=self.solve_x2(y).sqrt()
        if x is None or (x.iszero() and xs!=x.sign()):
            return (None,None)
        #If sign of x isn't correct, flip it.
        if x.sign()!=xs: x=-x
        # Return the constructed point.
        return (x,y)
    def encode_base(self,b):
        xp,yp=self.x/self.z,self.y/self.z
        #Encode y.
        s=bytearray(yp.tobytes(b))
        #Add sign bit of x to encoding.
        if xp.sign()!=0: s[(b-1)//8]|=1<<(b-1)%8
        return s
    
    def copy(self):
        return EdwardsPoint(x=self.x, y=self.y)

    def zero(self):
        return EdwardsPoint(x=0, y=1)
    
    def mult(self, n):
        m = Mod(n, self.curve.L).lift().digits(2)  ## obter a representação binária do argumento "n"
        Q = self.copy()
        A = self.zero()
        for b in m:
            if b == 1:
                A.soma(Q)
            Q.duplica()
        return A
    #Check that two points are equal.
    def eq(self, other):
        return self.x == other.x and self.y == other.y
    #Check if two points are not equal.
    def ne(self,y):
        return not (self==y)
