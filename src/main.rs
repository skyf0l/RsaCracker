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
    /// Cipher message.
    #[clap(short)]
    c: Option<IntegerArg>,
    /// Modulus.
    #[clap(short)]
    n: Option<IntegerArg>,
    /// Public exponent. Default: 65537
    #[clap(short, default_value = "65537")]
    e: IntegerArg,
    /// Prime number p.
    #[clap(short)]
    p: Option<IntegerArg>,
    /// Prime number q.
    #[clap(short)]
    q: Option<IntegerArg>,
    /// Phi or Euler's totient function of n. (p-1)(q-1)
    #[clap(long)]
    phi: Option<IntegerArg>,
    /// dP or dmp1 CRT exponent. (d mod p-1)
    #[clap(long)]
    dp: Option<IntegerArg>,
    /// dQ or dmq1 CRT exponent. (d mod q-1)
    #[clap(long)]
    dq: Option<IntegerArg>,
    /// The sum of the two primes p and q.
    #[clap(long)]
    sum_pq: Option<IntegerArg>,
    /// Public key PEM file.
    #[clap(long)]
    publickey: Option<String>,
    /// Print the private key in PEM format.
    #[clap(long)]
    printkey: bool,
    /// Print the RSA key variables n, e, p, q and d.
    #[clap(long)]
    dumpkey: bool,
    /// Print the extended RSA key variables n, e, p, q, d, dP, dQ, pInv and qInv.
    #[clap(long)]
    dumpextkey: bool,
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
            c: args.c.map(|n| n.0),
            n: args.n.map(|n| n.0),
            e: args.e.0,
            p: args.p.map(|n| n.0),
            q: args.q.map(|n| n.0),
            phi: args.phi.map(|n| n.0),
            dp: args.dp.map(|n| n.0),
            dq: args.dq.map(|n| n.0),
            sum_pq: args.sum_pq.map(|n| n.0),
        }
    };
    let (private_key, uncipher) = run_attacks(&params).ok_or("No attack succeeded")?;

    if args.printkey || args.dumpkey || args.dumpextkey {
        if let Some(private_key) = &private_key {
            if args.printkey {
                println!("{}", private_key.to_pem().unwrap());
            }
            if args.dumpkey || args.dumpextkey {
                println!("Private key :");
                println!("n = {}", private_key.n);
                println!("e = {}", private_key.e);
                println!("p = {}", private_key.p);
                println!("q = {}", private_key.q);
                println!("d = {}", private_key.d);
            }
            if args.dumpextkey {
                println!("Extended private key :");
                let dp = private_key.d.clone() % (&private_key.p - Integer::from(1));
                println!("dP = {dp}",);
                let dq = private_key.d.clone() % (&private_key.q - Integer::from(1));
                println!("dQ = {dq}",);
                let p_inv = Integer::from(private_key.p.invert_ref(&private_key.q).unwrap());
                println!("pInv = {p_inv}",);
                let q_inv = Integer::from(private_key.q.invert_ref(&private_key.p).unwrap());
                println!("qInv = {q_inv}",);
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
