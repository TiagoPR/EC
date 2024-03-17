from sage.ntt import ntt, intt

def split(f):
    f_plus = [f[i] for i in range(len(f)) if i % 2 == 0]
    f_minus = [f[i] for i in range(len(f)) if i % 2 != 0]
    return f_plus, f_minus

def polynomial_NTT(f, xi):
    N = len(f)
    if N == 1:
        return (f[0],)
    else:
        f_plus, f_minus = split(f)
        bar_f_plus = ntt(xi^2, N//2, f_plus)
        bar_f_minus = ntt(xi^2, N//2, f_minus)
        s = xi
        bar_f = [0] * N
        for i in range(N//2):
            bar_f[i] = bar_f_plus[i] + s * bar_f_minus[i]
            bar_f[i + N//2] = bar_f_plus[i] - s * bar_f_minus[i]
            s *= xi^2
        return tuple(bar_f)

# Example usage
N = 8
f = [1, 2, 3, 4, 5, 6, 7, 8]  # Example input polynomial
xi = 3  # Example value of xi

# Call the function
result = polynomial_NTT(f, xi)
print(result)
