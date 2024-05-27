import hashlib

class DILITHIUM:

    # Parâmetros da técnica DILITHIUM - NIST level 5 - 5+
    def __init__(self, nivel):
        self.d = 13
        #2^23 − 2^13 + 1
        self.q = 8380417
        
        if nivel == 2:
            self.n = 128
            self.k = 4
            self.l = 4
            self.eta = 2
            self.tau = 39 
            self.beta = 78 
            self.gama_1 = 2^17
            self.gama_2 = (self.q)-1/88
            self.omega = 80 
        elif nivel == 3:
            self.n = 192 
            self.k = 6
            self.l = 5
            self.eta = 4
            self.tau = 49 
            self.beta = 196 
            self.gama_1 = 2^19
            self.gama_2 = (self.q)-1/32
            self.omega = 55
        elif nivel == 5:
            self.n = 256
            self.k = 8
            self.l = 7
            self.eta = 2
            self.tau = 60
            self.beta = 120
            self.gama_1 = 2^19
            self.gama_2 = (self.q)-1/32
            self.omega = 75
        
        # Anéis 
        Zx.<x> = ZZ[]
        Zq.<z> = PolynomialRing(GF(self.q))
        self.Rq = QuotientRing(Zq,z^self.n+1)
        self.R = QuotientRing(Zx, x^self.n+1)
    
        # Espaço matrix 
        self.Mr  = MatrixSpace(self.Rq,self.k,self.l)

    # Algoritmo de geração de chaves  
    def key_gen(self):
        # Matriz A
        A = self.gen_a()
        
        # Vetores s1 e s1
        s1 = self.gen_s(self.eta, self.l)
        s2 = self.gen_s(self.eta, self.k)

        t = A*s1 + s2
        
        p_key = (A,t)
        s_key = (A,t,s1,s2)
        
        return p_key, s_key
        
    # Matriz A em Rq
    def gen_a(self):
        K = []
        for i in range(self.k*self.l):
            K.append(self.Rq.random_element())
        A = self.Mr(K)
        return A
    
    # Vetores S em Rq com o coeficiente até 'limit' e tamanho 'size'
    def gen_s(self, limit, size):
        vetor = MatrixSpace(self.Rq,size,1)
        K = []
        for i in range(size):
            poli = []
            for j in range(self.n):
                poli.append(randint(1,limit))
            K.append(self.Rq(poli))
        S = vetor(K)
        return S

    def sign(self, s_key, message): 
        A, t, s1, s2 = s_key

        z = 0
        while(z==0):
            # Vetor y
            y = self.gen_s(int(self.gama_1-1) , self.l)

            # w := Ay
            w = A * y

            # w1 := HighBits(w, 2*γ2)
            w1 = self.hb_poli(w, 2*self.gama_2)
            
            # c ∈ Bτ := H(M || w1)
            c = self.hash(message.encode(), str(w1).encode())
            cq = self.Rq(c)
            
            # z := y + cs1
            z = y + cq*s1
            
            if self.norma_inf_vet(z)[0] >= self.gama_1 - self.beta or self.norma_inf_matriz(self.lb_poli(A*y-cq*s2,2*self.gama_2)) >= self.gama_2-self.beta:
                z=0
            else:
                sigma = (z,c)
                return sigma
            
    # Extrai os “higher-order” bits do decompose     
    def high_bits(self, r, alpha):
        (r1,_) = self.decompose(r, alpha)
        return r1
    
    # Extrai os “lower-order” bits do decompose
    def low_bits(self, r, alpha):
        (_,r0) = self.decompose(r, alpha)
        return r0

    def decompose(self, r, alpha):
        r = mod(r, self.q)
        r0 = int(mod(r,int(alpha)))
        if (r-r0 == self.q-1):
            r1 = 0
            r0 = r0-1
        else:
            r1 = (r-r0)/int(alpha)
        return (r1,r0)
    
    def hb_poli(self, poli,alpha):
        k = poli.list()
        for i in range(len(k)):
            h = k[i]
            h = h.list()
            for j in range(len(h)):
                h[j]=self.high_bits(int(h[j]), alpha)
            k[i]=h
        return k
    
    def lb_poli(self,poli,alpha):
        k = poli.list()
        for i in range(len(k)):
            h = k[i]
            h = h.list()
            for j in range(len(h)):
                h[j] = self.low_bits(int(h[j]),alpha)
            k[i] = h
        return k
    
    # Converte de Bytes para bits 
    def access_bit(self, data, num):                              
        base = int(num // 8)
        shift = int(num % 8)
        return (data[base] & (1<<shift)) >> shift
    
    # Implementação da função "Hashing to a Ball"
    def sample_in_ball(self,r):
        sl = [self.access_bit(r[:8],i) for i in range(len(r[:8])*8)]
        # Inciar a partir do index 8
        k = 8 
        c = [0] * 256 

        for i in range (256-self.tau, 256):
            while (int(r[k])>i):
                k +=1 
                
            j = int(r[k])
            k += 1
            s = int(sl[i-196])
  
            c[i] = c[j]
            c[j] = (-1)^(s)
        return c

    def shake(self,a,b):
        shake = hashlib.shake_256()
        shake.update(a)
        shake.update(b)
        s = shake.digest(int(256))
        return s

    def hash(self,a,b):
        r = self.shake(a,b)
        c = self.sample_in_ball(r)
        return c
    
    def norma_inf(self,pol):
        J = pol.list()
        for i in range(len(J)):
            k = J[i]
            K = k.list()
            for j in range(len(K)):
                K[j] = abs(int(K[j]))
            J[i] = K
        L = []
        for i in range(len(J)):
            L.append(max(J[i]))
        return max(L)

    def norma_inf_vet(self,vector):
        for i in range(vector.nrows()):
            norm = self.norma_inf(vector[i])
            vector[i] = norm
        return max(vector)
    
    
    def norma_inf_matriz(self,matrix):
        L = []
        for i in range(len(matrix)):
            k = matrix[i]
            for j in range(len(k)):
                if k[j] < 0:
                    k[j] = abs(k[j])
                L.append(max(k))
        for i in range(len(L)):
            J = []
            J.append(max(L))
        return J[0]
    
    # Verifica a assinatura na mensagem utilizando a p_key
    def verify(self,p_key, message, sigma):
        A,t = p_key
        z,c = sigma
        
        cq = self.Rq(c)
        
        w1 = self.hb_poli(A*z - cq*t, 2*self.gama_2)
    
        u = str(w1).encode()
        k = message.encode()
        c_ = self.hash(k,u)
        
        return self.norma_inf_vet(z)[0] < self.gama_1 - self.beta and c_ == c

dilithium = DILITHIUM(nivel=3)

message = 'This is the message'

wrong_message = 'This message is wrong'

p_key,s_key = dilithium.key_gen()

sigma = dilithium.sign(s_key, message)

result = dilithium.verify(p_key, message, sigma)

print("Verifying the correct message:")
if result:
    print("Valid signature.")
else:
    print("Invalid signature.")

wrong_result = dilithium.verify(p_key, wrong_message, sigma)

print("Verifying the incorrect message:")
if wrong_result:
    print("Valid signature.")
else:
    print("Invalid signature.")