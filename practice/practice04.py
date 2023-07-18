def lcg(a, c, m, x):
    return (a * x + c) % m

a = 2147483629
c = 2147483587
m = 2**31 - 1
r = 1

sample_count = 2000
x = []
for _ in range(sample_count):
    r = lcg(a, c, m, r)
    x.append(r)

# import matplotlib.pyplot as plt

# xs = []
# ys = []
# zs = []

# for i in range(sample_count-2):
#     xs.append(x[i])
#     ys.append(x[i+1])
#     zs.append(x[i+2])

# ax2d = plt.subplot(121)
# ax3d = plt.subplot(122, projection='3d')
# ax2d.scatter(xs, ys)
# ax3d.scatter(xs, ys, zs)
# plt.show()

def calc_det(a, b, c, d):
    return b*d - c*c - (a*d - c*b) + a*c - b*b

from math import gcd

mm = 0
for i in range(10):
    mm = gcd(mm, calc_det(x[i], x[i+1], x[i+2], x[i+3]))

print(mm, m)

aa = (x[1] - x[2]) * pow(x[0]-x[1], -1, mm) % mm
print(aa, a)

cc = (x[1] - aa*x[0]) % mm
print(c, cc)