# RSA Solver

[![Build](https://github.com/skyf0l/RsaCracker/actions/workflows/ci.yml/badge.svg)](https://github.com/skyf0l/RsaCracker/actions/workflows/ci.yml)
[![Crate.io](https://img.shields.io/crates/v/rsacracker.svg)](https://crates.io/crates/rsacracker)
[![codecov](https://codecov.io/gh/skyf0l/rsacracker/branch/master/graph/badge.svg)](https://codecov.io/gh/skyf0l/rsacracker)

Powerful RSA cracker for CTFs. Supports RSA, X509, OPENSSH in PEM and DER formats.

RsaCracker provides a simple interface to crack RSA keys and ciphers. With a collection of thousands of attacks, no key <!-- or at least that's what I hope --> can survive against RsaCracker!

## Installation

From crates.io:

```console
cargo install rsacracker
```

Note: To build on windows, you need to use [MSYS2](https://www.msys2.org/). This is required because of the [rug](https://crates.io/crates/rug) dependency. See [building-on-windows](https://gitlab.com/tspiteri/gmp-mpfr-sys#building-on-windows) for more information.

## Usage

```text
Usage: rsacracker [OPTIONS]

Options:
  -c, --cipher <CIPHER>            Cipher message: the message to uncipher
  -f, --cipherfile <CIPHERFILE>    Cipher message file: the file to uncipher
  -n <N>                           Modulus
  -e <E>                           Public exponent. Default: 65537 [default: 65537]
  -p <P>                           Prime number p
  -q <Q>                           Prime number q
  -d <D>                           Private exponent
      --phi <PHI>                  Phi or Euler's totient function of n. (p-1)(q-1)
      --dp <DP>                    dP or dmp1 CRT exponent. (d mod p-1)
      --dq <DQ>                    dQ or dmq1 CRT exponent. (d mod q-1)
      --qinv <QINV>                qInv or iqmp CRT coefficient. (q^-1 mod p)
      --pinv <PINV>                pInv or ipmq CRT coefficient. (p^-1 mod q)
      --sum-pq <SUM_PQ>            The sum of the two primes p and q
      --dlog                       Discrete logarithm attack. When c and e are swapped in the RSA encryption formula. (e^c mod n)
  -k, --key <KEY>                  Public or private key file. (RSA, X509, OPENSSH in PEM and DER formats.)
      --password <PASSWORD>        Private key password/passphrase if encrypted
      --public                     Print the public key in PEM format
      --private                    Print the private key in PEM format
      --addpassword <ADDPASSWORD>  Add a password/passphrase to the private key
      --dump                       Print all the input parameters
      --dumpkey                    Print the private RSA key variables n, e, p, q and d
      --dumpextkey                 Print the extended RSA key variables n, e, p, q, d, dP, dQ, pInv and qInv
      --factors                    Print all factors of n
  -t, --threads <THREADS>          Number of threads to use. Default: number of CPUs [default: 12]
  -a, --attack <ATTACK>            Specify attacks to run. Default: all. (e.g. --attacks ecm,wiener,sparse)
      --exclude <EXCLUDE>          Specify attacks to exclude. Default: none. (e.g. --exclude ecm,wiener,sparse)
      --list                       List all available attacks
  -h, --help                       Print help
  -V, --version                    Print version
```

## Examples

### Uncipher a message from a public key

```console
$ rsacracker --key public.pem -c 0xdeadbeef
```

### Uncipher a message from n and e

```console
$ rsacracker -c 0xdeadbeef -n 123...789 -e 65537
```

### Uncipher a message from n, e and other known values

```console
$ rsacracker -c 0xdeadbeef -n 123...789 -e 65537 --phi 123 --dp 123 --dq 123 --qinv 123 --pinv 123
```

### Uncipher a file from a public key

```console
$ rsacracker --key public.pem -f secret.txt.enc
```

### Run a specific attack with arguments

```console
$ rsacracker --attack known_phi -n 123...789 -e 65537 --phi 0xdeadbeef
```

### Generate a private key from a public key

```console
$ rsacracker --key public.pem --private
```

### Generate a public key from e and n

```console
$ rsacracker -e 65537 -n 0xdeadbeef --public
```

### Dump private key secrets

```console
$ rsacracker --key private.pem --dumpkey
$ rsacracker --key private.pem --dumpextkey
```

### Remove password from a private key

```console
$ rsacracker --key private.pem --password R54Cr4ck3R --private
```

### Add password to a private key

```console
$ rsacracker --key private.pem --addpassword R54Cr4ck3R --private
```

### Show all factors of n

```console
$ rsacracker -n 123...789 --factors
```

### Run discrete logarithm attack: when c and e are swapped in the RSA encryption formula (e^c mod n)

```console
$ rsacracker --key public.pem -c 0xdeadbeef --dlog
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
