#EdDSA scheme.
class EdDSA:
    #Create a new scheme object, with the specified PureEdDSA base
    #scheme and specified prehash.
    def __init__(self,pure_scheme,prehash):
        self.__pflag = True
        self.__pure=pure_scheme
        self.__prehash=prehash
        if self.__prehash is None:
            self.__prehash = lambda x,y:x
            self.__pflag = False
    # Generate a key.  If privkey is none, it generates a random
    # privkey key, otherwise it uses a specified private key.
    # Returns pair (privkey, pubkey).

    # Sign message msg using specified key pair.
    def sign(self,privkey,pubkey,msg,ctx=None):
        if ctx is None: ctx=b"";
        return self.__pure.sign(privkey,pubkey,self.__prehash(msg,ctx),\
            ctx,self.__pflag)
    # Verify signature sig on message msg using public key pubkey.
    def verify(self,pubkey,msg,sig,ctx=None):
        if ctx is None: ctx=b"";
        return self.__pure.verify(pubkey,self.__prehash(msg,ctx),sig,\
            ctx,self.__pflag)

Ed448 = EdDSA(pEd448,None)