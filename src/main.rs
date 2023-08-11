use base64::{engine::general_purpose, Engine};
use clap::{command, Parser};
use discrete_logarithm::discrete_log_with_factors;
use display_bytes::display_bytes;
use main_error::MainError;
use rug::Integer;
use std::{collections::HashMap, time::Duration};

use rsacracker::{integer_to_bytes, integer_to_string, Parameters};
use update_informer::{registry, Check};

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
        } else if let Some(n) = n.strip_prefix("b64") {
            let bytes = general_purpose::STANDARD
                .decode(n.as_bytes())
                .or(Err("Invalid base64 number".to_string()))?;
            Ok(Self(Integer::from_digits(&bytes, rug::integer::Order::Msf)))
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
    /// Private exponent.
    #[clap(short)]
    d: Option<IntegerArg>,
    /// Phi or Euler's totient function of n. (p-1)(q-1)
    #[clap(long)]
    phi: Option<IntegerArg>,
    /// dP or dmp1 CRT exponent. (d mod p-1)
    #[clap(long, alias = "dmp1")]
    dp: Option<IntegerArg>,
    /// dQ or dmq1 CRT exponent. (d mod q-1)
    #[clap(long, alias = "dmq1")]
    dq: Option<IntegerArg>,
    /// qInv or iqmp CRT coefficient. (q^-1 mod p)
    #[clap(long, alias = "iqmp")]
    qinv: Option<IntegerArg>,
    /// pInv or ipmq CRT coefficient. (p^-1 mod q)
    #[clap(long, alias = "ipmq")]
    pinv: Option<IntegerArg>,
    /// The sum of the two primes p and q.
    #[clap(long)]
    sum_pq: Option<IntegerArg>,
    /// Discrete logarithm attack. When c and e are swapped in the RSA encryption formula. (e^c mod n)
    #[clap(long, alias = "dislog", requires("c"))]
    dlog: bool,
    /// Public key PEM/X509/openssh file.
    #[clap(long)]
    publickey: Option<String>,
    /// Print the RSA public key variables n and e, and exit.
    #[clap(long, requires("publickey"))]
    dumppublickey: bool,
    /// Private key PEM file.
    #[clap(long)]
    privatekey: Option<String>,
    /// Private key password/passphrase if encrypted.
    #[clap(long)]
    password: Option<String>,
    /// Print the private key in PEM/openssh format.
    #[clap(long)]
    printkey: bool,
    /// Add a password/passphrase to the private key.
    #[clap(long, requires("printkey"))]
    addpassword: Option<String>,
    /// Print the RSA key variables n, e, p, q and d.
    #[clap(long)]
    dumpkey: bool,
    /// Print the extended RSA key variables n, e, p, q, d, dP, dQ, pInv and qInv.
    #[clap(long)]
    dumpextkey: bool,
    /// Number of threads to use. Default: number of CPUs
    #[cfg(feature = "parallel")]
    #[clap(short, long, default_value_t = num_cpus::get())]
    threads: usize,
}

fn main() -> Result<(), MainError> {
    let pkg_name = env!("CARGO_PKG_NAME");
    let current_version = env!("CARGO_PKG_VERSION");
    let informer = update_informer::new(registry::Crates, pkg_name, current_version)
        .interval(Duration::from_secs(60 * 60));
    if let Ok(Some(new_version)) = informer.check_version() {
        eprintln!("A new release of {pkg_name} is available: v{current_version} -> {new_version}");
        eprintln!("You can update by running: cargo install {pkg_name}\n");
    }

    let args = Args::parse();

    let mut params = Parameters {
        c: args.c.map(|n| n.0),
        n: args.n.map(|n| n.0),
        e: args.e.0,
        p: args.p.map(|n| n.0),
        q: args.q.map(|n| n.0),
        d: args.d.map(|n| n.0),
        phi: args.phi.map(|n| n.0),
        dp: args.dp.map(|n| n.0),
        dq: args.dq.map(|n| n.0),
        qinv: args.qinv.map(|n| n.0),
        pinv: args.pinv.map(|n| n.0),
        sum_pq: args.sum_pq.map(|n| n.0),
    };
    if let Some(public_key) = args.publickey {
        let bytes = std::fs::read(public_key)?;
        let public_key_params = Parameters::from_public_key(&bytes).ok_or("Invalid public key")?;
        if args.dumppublickey {
            println!("Public key :");
            println!("n = {}", public_key_params.n.unwrap());
            println!("e = {}", public_key_params.e);
            return Ok(());
        }
        params += public_key_params;
    };
    if let Some(private_key) = args.privatekey {
        let bytes = std::fs::read(private_key)?;
        params += Parameters::from_private_key(&bytes, args.password.as_deref())
            .ok_or("Invalid private key")?;
    };
    #[cfg(feature = "parallel")]
    let solution =
        rsacracker::run_parallel_attacks(&params, args.threads).ok_or("No attack succeeded")?;
    #[cfg(not(feature = "parallel"))]
    let solution = rsacracker::run_sequence_attacks(&params).ok_or("No attack succeeded")?;

    println!("Succeeded with attack: {}", solution.attack);

    if args.printkey || args.dumpkey || args.dumpextkey {
        if let Some(private_key) = &solution.pk {
            if args.printkey {
                println!("{}", private_key.to_pem(&args.addpassword).unwrap());
            }
            if args.dumpkey || args.dumpextkey {
                println!("Private key:");
                println!("n = {}", private_key.n);
                println!("e = {}", private_key.e);
                if private_key.other_factors.is_empty() {
                    println!("p = {}", private_key.p);
                    println!("q = {}", private_key.q);
                } else {
                    for (i, p) in private_key.factors().iter().enumerate() {
                        println!("p{} = {}", i + 1, p);
                    }
                }
                println!("d = {}", private_key.d);
            }
            if args.dumpextkey {
                println!("Extended private key:");
                println!("phi = {}", private_key.phi);
                println!("dP = {}", private_key.dp());
                println!("dQ = {}", private_key.dq());
                println!("pInv = {}", private_key.pinv());
                println!("qInv = {}", private_key.qinv());
            }
        } else {
            eprintln!("No private key found");
        }
    }

    if let Some(uncipher) = solution.m {
        println!("Unciphered data:");
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

        if args.dlog {
            if let Some(pk) = &solution.pk {
                println!("Compute discrete logarithm...");
                if let Ok(dlog) = discrete_log_with_factors(
                    &pk.n,
                    &params.c.unwrap(),
                    &pk.e,
                    &HashMap::from_iter(pk.factors().into_iter().map(|p| (p, 1))),
                ) {
                    println!("Int = {dlog}");
                    println!("Hex = 0x{dlog:02x}");
                    if let Some(str) = integer_to_string(&dlog) {
                        println!("String = \"{str}\"");
                    } else {
                        println!("Bytes = b\"{}\"", display_bytes(&integer_to_bytes(&dlog)));
                    }
                } else {
                    println!("Discrete logarithm failed");
                }
            } else {
                println!("Discrete logarithm requires private key");
            }
        }
    }

    if !solution.ms.is_empty() {
        println!("Multiple unciphered data found:");
        for uncipher in solution.ms {
            println!("\nInt = {uncipher}");
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
    }

    Ok(())
}
