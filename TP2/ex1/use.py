import hashlib

F = FiniteField(2**256-2**32-2**9 -2**8 - 2**7 - 2**6 - 2**4 - 1)
a  = 0
b  = 7
E  = EllipticCurve(F, [a, b])
G  = E((55066263022277343669578718895168534326250603453777594175500187360389116729240, 
32670510020758816978083085130507043184471273380659243275938904335757337482424))
n  = 115792089237316195423570985008687907852837564279074904382605163141518161494337
h  = 1
Fn = FiniteField(n)

def hashit(msg):  
  return Integer('0x' + hashlib.sha256(msg.encode()).hexdigest())

def keygen():
  d = randint(1, n - 1)
  Q = d * G
  return (Q, d)

def ecdsa_sign(d, m):
  r = 0
  s = 0
  while s == 0:
    k = 1
    while r == 0:
      k = randint(1, n - 1)
      Q = k * G
      (x1, y1) = Q.xy()
      r = Fn(x1)
    e = hashit(m)
    s = Fn(k) ^ (-1) * (e + d * r)
  return [r, s]

def ecdsa_verify(Q, m, r, s):
  e = hashit(m)
  w = s ^ (-1)
  u1 = (e * w)
  u2 = (r * w)
  P1 = Integer(u1) * G
  P2 = Integer(u2) * Q
  X = P1 + P2
  (x, y) = X.xy()
  v = Fn(x)
  return v == r


(Q, d) = keygen()
m = 'My Message'

[r, s] = ecdsa_sign(d, m)
result = ecdsa_verify(Q, m, r, s)

print (f"Message: {m}")
print (f"Public Key: {Q.xy()}")
print (f"Private Key: {d}")

print ("=== Signature ===")
print (f" r = {r}")
print (f" s = {s}")
print (f"Verification: {result}")
