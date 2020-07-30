#!/usr/bin/python2

from sympy.ntheory.modular import crt
import requests

# factordb request
def getPrimes(N, tryToFactorize=False):
    api_url = 'http://factordb.com/api?query='
    web_url = 'http://factordb.com/index.php?query='
    try:
        result = requests.get(api_url + str(N))
    except:
        print('Can\'t connect to factordb.com')
        exit()

    primes = []
    for prime_data in result.json().get('factors'):
        for i in range(prime_data[1]):
            primes.append(int(prime_data[0]))

    if tryToFactorize == False and len(primes) == 1 and result.json().get('status') == 'C':
        # unknow (api not factorize it)
        try:
            requests.get(web_url + str(N))
        except:
            print('Can\'t connect to factordb.com')
            exit()
        return getPrimes(N, tryToFactorize=True)

    return primes

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

def find_root(n, x):
    low = 0
    high = n
    while low < high:
        mid = (low + high) // 2
        if mid ** x < n:
            low = mid + 1
        else:
            high = mid
    return low

# attacks
def solveFromPrimes(primes, e, c):
    N = 1
    phi = 1
    for prime in primes:
        N *= prime
        phi *= (prime - 1)
    d = inverse(e, phi)
    m = pow(c, d, N)
    return m

def primesKnownAttack():
    p = int(input('p: '))
    q = int(input('q: '))
    e = int(input('e: '))
    c = int(input('c: '))

    m = solveFromPrimes([p, q], e, c)
    return m

def factorizationAttack():
    N = int(input('N: '))
    e = int(input('e: '))
    c = int(input('c: '))

    primes = getPrimes(N)
    if len(primes) < 2:
        print('Can\'t factorize N...')
        exit()
    m = solveFromPrimes(primes, e, c)
    return m

def lowExponentAttack():
    N = [0] * 3
    c = [0] * 3
    for id in range(3):
        N[id] = int(input('n' + str(id + 1) + ': '))
    for id in range(3):
        c[id] = int(input('c' + str(id + 1) + ': '))
    
    x = crt(N, c)[0]
    m = find_root(x, 3)
    if x != m ** 3:
        print('Can\'t find the cube root...')
        exit()
    return m

attacks = [
    ['Primes known (p, q, e, c)', primesKnownAttack],
    ['Factorization (n, e, c)', factorizationAttack],
    ['Low exponent (e = 3, n1, n2, n3, c1, c2, c3)', lowExponentAttack]
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
    except Exception as e:
        print e
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