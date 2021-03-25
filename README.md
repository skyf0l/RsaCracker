# RSA Solver

Ctf tool to quickly solve RSA cipher

# Config

```bash
$ pip3 install --user -r requirements.txt
```

# Attacks

- Primes known
- Factorization
- Low exponent
- Low plaintext (m\*\*e < n)
- Low cipher (m\*\*e just barely larger than n)
- Too big exponent

# Exemple

```
$ ./rsasolver.py
Chose an attack:
 1/ Primes known (p, q, e, c)
 2/ Factorization (n, e, c)
 3/ Low exponent (e = 3, n1, n2, n3, c1, c2, c3)
> 2
N: 1076464028341992536199809615911537893692586697
e: 65537
c: 862369381078327546132185807811079056687202787

-> m(dec): 99525074994170507913687585
-> m(from dec): RSA Solver!
```
