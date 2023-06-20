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
    /// Modulus dP (d mod p-1)
    #[clap(long)]
    dp: Option<Integer>,
    /// Modulus dQ (d mod q-1)
    #[clap(long)]
    dq: Option<Integer>,
    /// Public exponent. Default: 65537
    #[clap(short, default_value = "65537")]
    e: Integer,
    /// Cipher message.
    #[clap(short)]
    c: Option<Integer>,
    /// Public key PEM file.
    #[clap(long)]
    publickey: Option<String>,
}

#[cfg(not(tarpaulin_include))]
fn main() -> Result<(), MainError> {
    let args = Args::parse();

    let params = if let Some(publickey) = args.publickey {
        let bytes = std::fs::read(publickey)?;
        Parameters::from_publickey(&bytes).ok_or("Invalid public key")?
    } else {
        Parameters {
            n: args.n,
            p: args.p,
            q: args.q,
            dp: args.dp,
            dq: args.dq,
            e: args.e,
            c: args.c.clone(),
        }
    };
    let (_private_key, uncipher) = run_attacks(&params)?;

    if let Some(uncipher) = uncipher {
        println!("uncipher = {}", uncipher);
    }

    Ok(())
}
