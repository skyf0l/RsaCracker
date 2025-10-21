# Multi-Key Attack Examples

This directory contains example input files demonstrating multi-key RSA attacks.

## Common Factor Attack

When two RSA keys share a common prime factor, the GCD of their moduli reveals that factor.

Example file: `common_factor.txt`

Usage:
```bash
rsacracker --raw examples/common_factor.txt --dump
```

## Common Modulus Attack

When the same modulus is used with different coprime public exponents to encrypt the same message, 
the plaintext can be recovered without factoring.

Example file: `common_modulus.txt`

Usage:
```bash
rsacracker --raw examples/common_modulus.txt
```

## File Format

Multi-key files use indexed parameters (n1, e1, c1, n2, e2, c2, etc.) to specify additional keys:

```
# Main key (optional)
n = 123...
e = 65537
c = 456...

# Additional keys
n1 = 789...
e1 = 65537
c1 = 101112...

n2 = 131415...
e2 = 3
c2 = 161718...
```

The parser automatically groups indexed parameters into separate key entries.
