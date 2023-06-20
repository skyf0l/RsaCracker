use clap::{command, Parser};
use display_bytes::display_bytes;
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
    /// dP or dmp1 CRT exponent. (d mod p-1)
    #[clap(long)]
    dp: Option<Integer>,
    /// dQ or dmq1 CRT exponent. (d mod q-1)
    #[clap(long)]
    dq: Option<Integer>,
    /// The sum of the two primes p and q.
    #[clap(long)]
    sum_pq: Option<Integer>,
    /// Public exponent. Default: 65537
    #[clap(short, default_value = "65537")]
    e: Integer,
    /// Cipher message.
    #[clap(short)]
    c: Option<Integer>,
    /// Public key PEM file.
    #[clap(long)]
    publickey: Option<String>,
    /// Print the private key in PEM format.
    #[clap(long)]
    printpriv: bool,
    /// Print the private key variables.
    #[clap(long)]
    dumppriv: bool,
}

#[cfg(not(tarpaulin_include))]
fn main() -> Result<(), MainError> {
    use rsacracker::{integer_to_bytes, integer_to_string};

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
            sum_pq: args.sum_pq,
            e: args.e,
            c: args.c.clone(),
        }
    };
    let (_private_key, uncipher) = run_attacks(&params).ok_or("No attack succeeded")?;

    if args.printpriv || args.dumppriv {
        if let Some(private_key) = &_private_key {
            if args.printpriv {
                println!("{}", private_key.to_pem().unwrap());
            }
            if args.dumppriv {
                println!("{:#?}", private_key);
            }
        } else {
            eprintln!("No private key found");
        }
    }

    if let Some(uncipher) = uncipher {
        println!("Unciphered data :");
        println!("Int = {uncipher}");
        println!("Hex = 0x{uncipher:02x}");
        if let Some(str) = integer_to_string(&uncipher) {
            println!("String = \"{str}\"");
        } else {
            println!(
                "Bytes = b\"{}\"",
                display_bytes(&integer_to_bytes(&uncipher))
            );
        }
    }

    Ok(())
}
