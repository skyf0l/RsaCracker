# RSA Cracker

[![Build](https://github.com/skyf0l/RsaCracker/actions/workflows/ci.yml/badge.svg)](https://github.com/skyf0l/RsaCracker/actions/workflows/ci.yml)
[![Crate.io](https://img.shields.io/crates/v/rsacracker.svg)](https://crates.io/crates/rsacracker)
[![Docker Image Version](https://img.shields.io/docker/v/skyf0l/rsacracker?logo=docker)](https://hub.docker.com/r/skyf0l/rsacracker)
[![codecov](https://codecov.io/gh/skyf0l/rsacracker/branch/main/graph/badge.svg)](https://codecov.io/gh/skyf0l/rsacracker)

Powerful RSA cracker for CTFs. Supports RSA, X509, OPENSSH in PEM and DER formats.

RsaCracker provides a simple, extensible interface to analyze and recover RSA private keys and to uncipher messages using a large collection of targeted attacks and heuristics.

## TLDR - Quick start
- Install: `cargo install rsacracker`
- Crack a public key: `rsacracker --key public.pem --dump`
- Uncipher a ciphertext: `rsacracker --key public.pem -c 0xdeadbeef`
- Uncipher a file: `rsacracker --key public.pem -f 0xdeadbeef -o result.bin`

NOTE: To build on windows, you need to use [MSYS2](https://www.msys2.org/). This is required because of the [rug](https://crates.io/crates/rug) dependency. See [building-on-windows](https://gitlab.com/tspiteri/gmp-mpfr-sys#building-on-windows) for more information.

## Usage

```text
Powerful RSA cracker for CTFs. Supports RSA, X509, OPENSSH in PEM and DER formats.

Usage: rsacracker [OPTIONS]

Options:
  -r, --raw <RAW>                  Retrieve values from raw file
  -c, --cipher <CIPHER>            Cipher: the message to uncipher. Can be specified multiple times for multi-key attacks
  -f, --cipherfile <CIPHERFILE>    Cipher file: the file to uncipher
  -o, --outfile <OUTFILE>          Write unciphered data to a file. If many unciphered data are found, they will be written to files suffixed with _1, _2, ...
  -n <N>                           Modulus. Can be specified multiple times for multi-key attacks
  -e <E>                           Public exponent. Default: 65537. Can be specified multiple times for multi-key attacks
  -p <P>                           Prime number p (supports wildcards: 0xDEADBEEF????, 10737418??, 0x...C0FFEE, 0xDEADBEEF..., etc.)
  -q <Q>                           Prime number q (supports wildcards: 0x????C0FFEE, ??741827, 0x...C0FFEE, 0xDEADBEEF..., etc.)
  -d <D>                           Private exponent
      --phi <PHI>                  Phi or Euler's totient function of n. (p-1)(q-1)
      --dp <DP>                    dP or dmp1 CRT exponent. (d mod p-1)
      --dq <DQ>                    dQ or dmq1 CRT exponent. (d mod q-1)
      --qinv <QINV>                qInv or iqmp CRT coefficient. (q^-1 mod p)
      --pinv <PINV>                pInv or ipmq CRT coefficient. (p^-1 mod q)
      --sum-pq <SUM_PQ>            The sum of the two primes p and q
      --diff-pq <DIFF_PQ>          The difference of the two primes p and q
      --dlog                       Discrete logarithm attack. When c and e are swapped in the RSA encryption formula. (e^c mod n)
  -k, --key <KEY>                  Public or private key file(s). (RSA, X509, OPENSSH in PEM and DER formats.) Can be specified multiple times for multi-key attacks
      --password <PASSWORD>        Private key password/passphrase if encrypted
      --public                     Print the public key in PEM format
      --private                    Print the private key in PEM format
      --addpassword <ADDPASSWORD>  Add a password/passphrase to the private key
      --showinputs                 Print all the input parameters
      --dump                       Print the private RSA key variables n, e, p, q and d
      --dumpext                    Print the extended RSA key variables n, e, p, q, d, dP, dQ, pInv and qInv
      --factors                    Print all factors of n
  -t, --threads <THREADS>          Number of threads to use. Default: number of CPUs
  -a, --attack <ATTACK>            Specify attacks to run. Default: all. (e.g. --attacks ecm,wiener,sparse)
      --exclude <EXCLUDE>          Specify attacks to exclude. Default: none. (e.g. --exclude ecm,wiener,sparse)
      --list                       List all available attacks
  -h, --help                       Print help
  -V, --version                    Print version
```

You can also use a dump as input:

```console
$ rsacracker [OPTIONS] < challenge.txt
[RESULTS]
$ cat challenge.txt | rsacracker [OPTIONS]
[RESULTS]
$ cat challenge.txt
c: 7839407718[...]0577093673
n = 9359619564[...]3745124619
e= 1595235523[...]6275096193
```

## Examples

### Uncipher a message from a public key and write it to a file

```console
rsacracker --key public.pem -c 0xdeadbeef -o result.txt
```

### Uncipher a message from n and e

```console
rsacracker -c 0xdeadbeef -n 123...789 -e 65537
```

### Uncipher a message from n, e and other known values

```console
rsacracker -c 0xdeadbeef -n 123...789 -e 65537 --phi 123 --dp 123 --dq 123 --qinv 123 --pinv 123
```

### Uncipher a file from a public key

```console
rsacracker --key public.pem -f secret.txt.enc
```

### Recover private key from partial prime information

When you know some bits/digits of a prime (MSB or LSB), you can use wildcards (`?`) in binary, octal, decimal, or hexadecimal notation:

```console
# Binary: MSB known (trailing wildcards)
rsacracker -n 123...789 -p 0b1101010???

# Octal: LSB known (leading wildcards)
rsacracker -n 123...789 -p 0o???777

# Decimal: MSB known (trailing wildcards)
rsacracker -n 2305843027467304993 -p 10737418??

# Decimal: LSB known (leading wildcards)
rsacracker -n 123...789 -p ??741827

# Hexadecimal: MSB known (trailing wildcards)
rsacracker -n 123...789 -p 0xDEADBEEF????

# Hexadecimal: LSB known (leading wildcards)  
rsacracker -n 123...789 -p 0x????C0FFEE
```

Each `?` represents one digit in the specified radix.

You can also use ellipsis (`...`) when the unknown length should be inferred from the modulus size:

```console
# Hexadecimal: LSB known (MSB length inferred)
rsacracker -n 123...789 -p 0x...C0FFEE

# Hexadecimal: MSB known (LSB length inferred)
rsacracker -n 123...789 -p 0xDEADBEEF...
```

### Run a specific attack with arguments

```console
rsacracker --attack known_phi -n 123...789 -e 65537 --phi 0xdeadbeef
```

### Generate a private key from a public key

```console
rsacracker --key public.pem --private
```

### Generate a public key from e and n

```console
rsacracker -e 65537 -n 0xdeadbeef --public
```

### Dump private key secrets

```console
rsacracker --key private.pem --dump
$ rsacracker --key private.pem --dumpext
```

### Remove password from a private key

```console
rsacracker --key private.pem --password R54Cr4ck3R --private
```

### Add password to a private key

```console
rsacracker --key private.pem --addpassword R54Cr4ck3R --private
```

### Show all factors of n

```console
rsacracker -n 123...789 --factors
```

### Run discrete logarithm attack: when c and e are swapped in the RSA encryption formula (e^c mod n)

```console
rsacracker --key public.pem -c 0xdeadbeef --dlog
```

### Multi-key attacks

RsaCracker supports attacks that require multiple RSA keys. You can provide multiple keys in several ways:

**Method 1: Via raw file with indexed notation**

```console
# Create a file with multiple keys (multikeys.txt)
# Common factor attack - when two keys share a common prime
n1 = 166162630914502531310583922419891282066165820974633135604215723500594369488785155668770814942798477925368262423257419073645831352835527789101770856835355683177962166057699839663569971312562086050531058716298108813024798653596850452010850976880829077654912494652271256054564920903881745267063001869548202922099
e1 = 65537
c1 = 123

n2 = 148455898656074447797752378503069279028991863906908832057033693077681993859745690328279867444062926638337203683279627319119630089306918893030699950731547426066997479055479829293964341682216330844958953722765260947532634616964944677851975839768164255655099799121904635086103339949975609477039895462111764318783
e2 = 65537

# Run the attack
rsacracker --raw multikeys.txt
```

**Method 2: Via multiple --key parameters**

```console
# Provide multiple key files directly via CLI
rsacracker --key key1.pem --key key2.pem --dump

# Works with any combination of key files
rsacracker --key public1.pem --key public2.pem --key public3.pem
```

**Method 3: Via multiple -n parameters**

```console
# Provide multiple moduli directly for common factor attacks
rsacracker -n 166209509310787961... -n 137801924148643799... --dump

# Can combine with other parameters
rsacracker -n 123456... -n 789012... -e 65537
```

**Method 4: Via multiple -c and -e parameters**

```console
# Common modulus attack with multiple ciphertexts and exponents
rsacracker -n 166270918338126577... -e 65537 -e 65539 -c 136917880321258914... -c 46689866063983112...

# Hastad's broadcast attack with multiple n, e, and c
rsacracker -n 123... -n 456... -n 789... -e 3 -c 100... -c 200... -c 300...
```

## Docker

From dockerhub:

```console
docker pull skyf0l/rsacracker
docker run -it --rm -v $PWD:/data skyf0l/rsacracker [args]
```

Or build it yourself:

```console
DOCKER_BUILDKIT=1 docker build . --file Dockerfile -t rsacracker
docker run -it --rm -v $PWD:/data rsacracker [args]
```

## License

Licensed under either of

- Apache License, Version 2.0
  ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license
  ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
