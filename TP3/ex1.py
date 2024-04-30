# Hidden Number Problem -> with this we can recover a secret value from a public value

# p - A prime number for our field.
p = next_prime(2^16) # 65537  p do professor

Fp = GF(p) # Fq

alpha = Fp.random_element() # s do professor

# n - The number of bits in `p`.
n = ceil(log(p, 2))

# l - The number of significant bits revealed by the oracle.
# Using parameters from Thereom 1.
l = ceil(sqrt(n)) + ceil(log(n, 2)) # k do professor


def msb(x):
    """
    Returns the MSB of x based on the global paramters p, l.
    """
    while True:
        z = Fp.random_element()
        answer = x - z
        if Integer(answer) < Integer(p) / 2^(l+1):
            break
    return z

def create_oracle(alpha):
    """
    Returns a randomized MSB oracle using the specified alpha value.
    """
    alpha = alpha
    def oracle():
        t = Fp.random_element() # xi do professor
        return t, msb((alpha * t) % p) # par (xi,ui) que corresponde ao oraculo
    return oracle

###########################################

# Precisamos agora de usar os reticulados para prevenir o HNP

# d - The number of oracle queries.
d = 2 * ceil(sqrt(n)) # sacado do pdf

######

def build_basis(oracle_inputs):
    """
    Returns a basis using the HNP game parameters and inputs to our oracle
    """
    basis_vectors = []
    for i in range(d):
        p_vector = [0] * (d+1)
        p_vector[i] = p
        basis_vectors.append(p_vector)
    basis_vectors.append(list(oracle_inputs) + [QQ(1)/QQ(p)])
    return Matrix(QQ, basis_vectors)

def approximate_closest_vector(basis, v):
    """
    Returns an approximate CVP solution using Babai's nearest plane algorithm.
    """
    BL = basis.LLL()
    G, _ = BL.gram_schmidt()
    _, n = BL.dimensions()
    small = vector(ZZ, v)
    for i in reversed(range(n)):
        c = QQ(small * G[i]) / QQ(G[i] * G[i])
        c = c.round()
        small -= BL[i] * c
    return (v - small).coefficients()

# Hidden alpha scalar
alpha = Fp.random_element() 
print("This is the original alpha: %d" % alpha)

# Create a MSB oracle using the secret alpha scalar
oracle = create_oracle(alpha)

# Using terminology from the paper: inputs = `t` values, answers = `a` values
inputs, answers = zip(*[ oracle() for _ in range(d) ])

# Build a basis using our oracle inputs
lattice = build_basis(inputs)
print("Solving CVP using lattice with basis:\n%s\n" % str(lattice))

# The non-lattice vector based on the oracle's answers
u = vector(ZZ, list(answers) + [0])
print("Vector of MSB oracle answers:\n%s\n" % str(u))

# Solve an approximate CVP to find a vector v which is likely to reveal alpha.
v = approximate_closest_vector(lattice, u)
print("Closest lattice vector:\n%s\n" % str(v))

# Confirm the recovered value of alpha matches the expected value of alpha.
recovered_alpha = (v[-1] * p) % p
assert recovered_alpha == alpha
print("Recovered alpha! Alpha is %d" % recovered_alpha)