def split(f):
    f_plus = [f[i] for i in range(len(f)) if i % 2 == 0]
    f_minus = [f[i] for i in range(len(f)) if i % 2 != 0]
    return f_plus, f_minus

def NTT(xi, N, f):
    if N == 1:
        return (f[0],)
    f_plus, f_minus = split(f)
    f_bar_plus = NTT(xi^2, N//2, f_plus)
    f_bar_minus = NTT(xi^2, N//2, f_minus)
    s = xi
    f_bar = [0]*N
    for i in range(N//2):
        f_bar[i] = f_bar_plus[i] + s * f_bar_minus[i]
        f_bar[i+N//2] = f_bar_plus[i] - s * f_bar_minus[i]
        s = s * xi^2
    return tuple(f_bar)
