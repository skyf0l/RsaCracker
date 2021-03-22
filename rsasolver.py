#!/usr/bin/python3

from sympy.ntheory.modular import crt
import requests
import string

# input

def get_num(label):
    n_str = input(label)
    if len(n_str) > 2 and (n_str[0:2] == '0x' or n_str[0:2] == '0X'):
        n = int(n_str, 16)
    else:
        n = int(n_str)
    return n

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

def rational_to_contfrac(x, y):
    # https://gist.github.com/mananpal1997/73d07cdc91d58b4eb5c818aaab2d38bd
    # Converts a rational x/y fraction into a list of partial quotients [a0, ..., an]
    a = x // y
    pquotients = [a]
    while a * y != x:
        x, y = y, x - a * y
        a = x // y
        pquotients.append(a)
    return pquotients

def convergents_from_contfrac(frac):
    # https://gist.github.com/mananpal1997/73d07cdc91d58b4eb5c818aaab2d38bd
    # computes the list of convergents using the list of partial quotients
    convs = []
    for i in range(len(frac)):
        convs.append(contfrac_to_rational(frac[0: i]))
    return convs

def contfrac_to_rational(frac):
    # https://gist.github.com/mananpal1997/73d07cdc91d58b4eb5c818aaab2d38bd
    # Converts a finite continued fraction [a0, ..., an] to an x/y rational.
    if len(frac) == 0:
        return (0, 1)
    num = frac[-1]
    denom = 1
    for _ in range(-2, -len(frac) - 1, -1):
        num, denom = frac[_] * num + denom, num
    return (num, denom)

def isqrt(n):
    # https://gist.github.com/mananpal1997/73d07cdc91d58b4eb5c818aaab2d38bd
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x

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
    p = get_num('p: ')
    q = get_num('q: ')
    e = get_num('e: ')
    c = get_num('c: ')

    m = solveFromPrimes([p, q], e, c)
    return m

def factorizationAttack():
    N = get_num('N: ')
    e = get_num('e: ')
    c = get_num('c: ')

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
        N[id] = get_num('n' + str(id + 1) + ': ')
    for id in range(3):
        c[id] = get_num('c' + str(id + 1) + ': ')

    x = crt(N, c)[0]
    m = find_root(x, 3)
    if x != m ** 3:
        print('Can\'t find the cube root...')
        exit()
    return m

def tooBigExponentAttack():
    N = get_num('N: ')
    e = get_num('e: ')
    c = get_num('c: ')

    frac = rational_to_contfrac(e, N)
    convergents = convergents_from_contfrac(frac)
    
    d = 0
    for (k, _d) in convergents:
        if k != 0 and (e * _d - 1) % k == 0:
            phi = (e * _d - 1) // k
            s = N - phi + 1
            # check if x*x - s*x + n = 0 has integer roots
            D = s * s - 4 * N
            if D >= 0:
                sq = isqrt(D)
                if sq * sq == D and (s + sq) % 2 == 0:
                    d = _d
    m = pow(c, d, N)
    return m

attacks = [
    ['Primes known (p, q, e, c)', primesKnownAttack],
    ['Factorization (n, e, c)', factorizationAttack],
    ['Low exponent (e = 3, n1, n2, n3, c1, c2, c3)', lowExponentAttack],
    ['Too big exponent, wiener (n, e, c)', tooBigExponentAttack]
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
    print()
    print('-> m(dec): ' + str(m))

    # from decimal
    try:
        plaintext = print(bytes.fromhex(hex(m).rstrip("L")[2:]).decode('utf-8'))
        if is_printable(plaintext):
            print('-> m(from dec): ' + plaintext)
    except:
        pass

    # from hex
    try:
        m_hex = str(m)
        plaintext = m_hex.decode('hex')
        if is_printable(plaintext):
            print('-> m(from hex): ' + plaintext)
    except:
        pass

def main():
    print('Chose an attack:')
    for id in range(len(attacks)):
        print(' ' + str(id + 1) + '/ ' + attacks[id][0])
    choice = input('> ')

    try:
        attackFunction = attacks[int(choice) - 1][1]
    except:
        exit()

    try:
        m = attackFunction()
    except Exception as e:
        print(e)
        print('Error while attempting to attack')
        exit()

    show_result(m)

if __name__ == '__main__':
    main()