use clap::{command, Parser};
use main_error::MainError;

use rug::Integer;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about)]
struct Args {
    #[clap(flatten)]
    options: Options,
}

/// Options.
#[derive(Parser, Debug, Clone)]
struct Options {
    /// Prime number p.
    #[clap(short)]
    p: Integer,
    /// Prime number q.
    #[clap(short)]
    q: Integer,
    /// Public exponent.
    #[clap(short)]
    e: Integer,
    /// Cipher message.
    #[clap(short)]
    c: Integer,
}

#[cfg(not(tarpaulin_include))]
fn main() -> Result<(), MainError> {
    let _args = Args::parse();

    let n = _args.options.p.clone() * _args.options.q.clone();
    let e = _args.options.e;
    let phi = (_args.options.p - 1) * (_args.options.q - 1);
    let d = e.invert(&phi).unwrap();
    let m = _args.options.c.pow_mod(&d, &n).unwrap();
    println!("m = {}", m);

    Ok(())
}
