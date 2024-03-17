def NTT(xi, N, f):
    if N == 1:
        return (f[0],)
    
    f_plus = [f[i] for i in range(0, N, 2)]
    f_minus = [f[i] for i in range(1, N, 2)]
    
    bar_f_plus = NTT(xi**2, N//2, f_plus)
    bar_f_minus = NTT(xi**2, N//2, f_minus)
    
    s = xi
    bar_f = [0] * N
    
    for i in range(N//2):
        bar_f[i] = bar_f_plus[i] + s * bar_f_minus[i]
        bar_f[i + N//2] = bar_f_plus[i] - s * bar_f_minus[i]
        s *= xi**2
    
    return tuple(bar_f)

# Exemplo de uso:
f = [1, 1, -2, -1]  # Coeficientes do polinómio f(w)
N = len(f)
xi = 2  # Raiz primitiva N-ésima da unidade, neste caso escolhemos 2

bar_f = NTT(xi, N, f)
print(bar_f)
