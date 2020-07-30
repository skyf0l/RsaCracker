#!/usr/bin/python2

from sympy.ntheory.modular import crt
import requests
import string

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
    p = int(raw_input('p: '))
    q = int(raw_input('q: '))
    e = int(raw_input('e: '))
    c = int(raw_input('c: '))

    m = solveFromPrimes([p, q], e, c)
    return m

def factorizationAttack():
    N = int(raw_input('N: '))
    e = int(raw_input('e: '))
    c = int(raw_input('c: '))

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
        N[id] = int(raw_input('n' + str(id + 1) + ': '))
    for id in range(3):
        c[id] = int(raw_input('c' + str(id + 1) + ': '))
    
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

def is_printable(plaintext):
    total = 0
    printable = 0

    for c in plaintext:
        if plaintext[total] in string.printable:
            printable += 1
        total += 1
    if total == 0:
        return 0
    return printable / total > 0.95

def show_result(m):
    print
    print '-> m(dec): ' + str(m)

    # from decimal
    try:
        m_hex = hex(m)[2:]
        if m_hex[len(m_hex) - 1] == 'L':
            m_hex = m_hex[:-1]
        plaintext = m_hex.decode('hex')
        if is_printable(plaintext):
            print '-> m(from dec): ' + plaintext
    except:
        pass

    # from hex
    try:
        m_hex = str(m)
        plaintext = m_hex.decode('hex')
        if is_printable(plaintext):
            print '-> m(from hex): ' + plaintext
    except:
        pass

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

    show_result(m)

if __name__ == '__main__':
    main()