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

## License

Licensed under either of

- Apache License, Version 2.0
  ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license
  ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
