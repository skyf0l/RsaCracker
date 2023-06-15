use clap::{command, Parser};
use main_error::MainError;

use rug::Integer;

use rsacracker::{run_attacks, Parameters};

#[derive(Parser, Debug, Clone)]
#[command(author, version, about)]
struct Args {
    /// Modulus.
    #[clap(short)]
    n: Option<Integer>,
    /// Prime number p.
    #[clap(short)]
    p: Option<Integer>,
    /// Prime number q.
    #[clap(short)]
    q: Option<Integer>,
    /// Public exponent. Default: 65537
    #[clap(short, default_value = "65537")]
    e: Integer,
    /// Cipher message.
    #[clap(short)]
    c: Option<Integer>,
}

#[cfg(not(tarpaulin_include))]
fn main() -> Result<(), MainError> {
    let args = Args::parse();

    let params = Parameters {
        n: args.n,
        p: args.p,
        q: args.q,
        e: args.e,
        c: args.c.clone(),
    };
    let (private_key, uncipher) = run_attacks(&params)?;

    if let Some(uncipher) = uncipher {
        println!("uncipher = {}", uncipher);
    }

    if let (Some(private_key), Some(c)) = (private_key, args.c) {
        let m = c.pow_mod(&private_key.d, &private_key.n).unwrap();
        println!("m = {}", m);
    }

    Ok(())
}
