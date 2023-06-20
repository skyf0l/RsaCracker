use clap::{command, Parser};
use display_bytes::display_bytes;
use main_error::MainError;

use rug::Integer;

use rsacracker::{run_attacks, Parameters};

#[derive(Debug, Clone)]
struct IntegerArg(Integer);

impl std::str::FromStr for IntegerArg {
    type Err = String;

    fn from_str(n: &str) -> Result<Self, Self::Err> {
        if let Some(n) = n.strip_prefix("0x") {
            Ok(Self(
                Integer::from_str_radix(n, 16).or(Err("Invalid hex number".to_string()))?,
            ))
        } else if let Some(n) = n.strip_prefix("0b") {
            Ok(Self(
                Integer::from_str_radix(n, 2).or(Err("Invalid binary number".to_string()))?,
            ))
        } else if let Some(n) = n.strip_prefix("0o") {
            Ok(Self(
                Integer::from_str_radix(n, 8).or(Err("Invalid octal number".to_string()))?,
            ))
        } else {
            Ok(Self(
                Integer::from_str(n).or(Err("Invalid number".to_string()))?,
            ))
        }
    }
}

#[derive(Parser, Debug, Clone)]
#[command(author, version, about)]
struct Args {
    /// Modulus.
    #[clap(short)]
    n: Option<IntegerArg>,
    /// Prime number p.
    #[clap(short)]
    p: Option<IntegerArg>,
    /// Prime number q.
    #[clap(short)]
    q: Option<IntegerArg>,
    /// dP or dmp1 CRT exponent. (d mod p-1)
    #[clap(long)]
    dp: Option<IntegerArg>,
    /// dQ or dmq1 CRT exponent. (d mod q-1)
    #[clap(long)]
    dq: Option<IntegerArg>,
    /// The sum of the two primes p and q.
    #[clap(long)]
    sum_pq: Option<IntegerArg>,
    /// Public exponent. Default: 65537
    #[clap(short, default_value = "65537")]
    e: IntegerArg,
    /// Cipher message.
    #[clap(short)]
    c: Option<IntegerArg>,
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
            n: args.n.map(|n| n.0),
            p: args.p.map(|n| n.0),
            q: args.q.map(|n| n.0),
            dp: args.dp.map(|n| n.0),
            dq: args.dq.map(|n| n.0),
            sum_pq: args.sum_pq.map(|n| n.0),
            e: args.e.0,
            c: args.c.map(|n| n.0),
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
