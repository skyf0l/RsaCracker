#!/usr/bin/python2

# math functions
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b//a) * y, y)

def inverse(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    return x % m

# attacks
def primesKnown():
    p = int(input('p: '))
    q = int(input('q: '))
    e = int(input('e: '))
    c = int(input('c: '))

    N = p * q
    phi = (q - 1) * (p - 1)
    d = inverse(e, phi)
    m = pow(c, d, N)
    return m

def factorization():
    return 8111412855914119614708549513070

def lowExponent():
    return 131090371366397862641757812

attacks = [
    ['Primes known (p, q, e, c)', primesKnown],
    ['Factorization (n, e, c)', factorization],
    ['Low exponent (e = 3, n1, n2, n3, c1, c2, c3)', lowExponent]
]

def main():
    print 'Chose an attack:'
    for id in range(len(attacks)):
        print ' ' + str(id + 1) + '/ ' + attacks[id][0]
    choice = raw_input('> ')

    try:
        attackFunction = attacks[int(choice) - 1][1]
    except:
        exit()

    try:
        m = attackFunction()
    except:
        print 'Error while attempting to attack'
        exit()

    print
    print '-> m(dec): ' + str(m)
    try:
        print '-> m(str): ' + hex(m)[2:-1].decode('hex')
    except:
        exit()

if __name__ == '__main__':
    main()