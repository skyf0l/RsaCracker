use base64::{engine::general_purpose, Engine};
use clap::{command, Parser};
use discrete_logarithm::discrete_log_with_factors;
use display_bytes::display_bytes;
use itertools::Itertools;
use main_error::MainError;
use rug::{
    integer::{IsPrime, Order},
    Integer,
};
use std::{sync::Arc, time::Duration};

use rsacracker::{integer_to_bytes, integer_to_string, Attack, Parameters, ATTACKS};
use update_informer::{registry, Check};

#[derive(Debug, Clone)]
struct IntegerArg(Integer);

impl std::str::FromStr for IntegerArg {
    type Err = String;

    fn from_str(n: &str) -> Result<Self, Self::Err> {
        if let Some(n) = n.strip_prefix("0x").or_else(|| n.strip_prefix("0X")) {
            Ok(Self(
                Integer::from_str_radix(n, 16).or(Err("Invalid hex number".to_string()))?,
            ))
        } else if let Some(n) = n.strip_prefix("0b").or_else(|| n.strip_prefix("0B")) {
            Ok(Self(
                Integer::from_str_radix(n, 2).or(Err("Invalid binary number".to_string()))?,
            ))
        } else if let Some(n) = n.strip_prefix("0o").or_else(|| n.strip_prefix("0O")) {
            Ok(Self(
                Integer::from_str_radix(n, 8).or(Err("Invalid octal number".to_string()))?,
            ))
        } else if let Some(n) = n.strip_prefix("b64").or_else(|| n.strip_prefix("B64")) {
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

#[derive(Debug, Clone)]
struct AttackArg(Arc<dyn Attack + Sync + Send>);

impl std::str::FromStr for AttackArg {
    type Err = String;

    fn from_str(attack: &str) -> Result<Self, Self::Err> {
        ATTACKS
            .iter()
            .find(|a| a.name() == attack)
            .map(|a| Self(a.clone()))
            .ok_or_else(|| format!("Unknown attack: {}", attack))
    }
}

#[derive(Parser, Debug, Clone)]
#[command(author, version, about)]
struct Args {
    /// Cipher message: the message to uncipher.
    #[clap(short, long)]
    cipher: Option<IntegerArg>,
    /// Cipher message file: the file to uncipher.
    #[clap(short = 'f', long)]
    cipherfile: Option<std::path::PathBuf>,
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
    #[clap(long, alias = "dislog")]
    dlog: bool,
    /// Public or private key file. (RSA, X509, OPENSSH in PEM and DER formats.)
    #[clap(short, long)]
    key: Option<String>,
    /// Private key password/passphrase if encrypted.
    #[clap(long)]
    password: Option<String>,
    /// Print the public key in PEM format.
    #[clap(long)]
    public: bool,
    /// Print the private key in PEM format.
    #[clap(long)]
    private: bool,
    /// Add a password/passphrase to the private key.
    #[clap(long, requires("private"))]
    addpassword: Option<String>,
    /// Print all the input parameters.
    #[clap(long)]
    dump: bool,
    /// Print the private RSA key variables n, e, p, q and d.
    #[clap(long)]
    dumpkey: bool,
    /// Print the extended RSA key variables n, e, p, q, d, dP, dQ, pInv and qInv.
    #[clap(long)]
    dumpextkey: bool,
    /// Print all factors of n.
    #[clap(long)]
    factors: bool,
    /// Number of threads to use. Default: number of CPUs
    #[cfg(feature = "parallel")]
    #[clap(short, long, default_value_t = num_cpus::get())]
    threads: usize,
    /// Specify attacks to run. Default: all. (e.g. --attacks ecm,wiener,sparse)
    #[clap(
        short,
        long,
        alias = "attacks",
        value_delimiter = ',',
        conflicts_with = "exclude"
    )]
    attack: Option<Vec<AttackArg>>,
    /// Specify attacks to exclude. Default: none. (e.g. --exclude ecm,wiener,sparse)
    #[clap(long, value_delimiter = ',', conflicts_with = "attack")]
    exclude: Option<Vec<AttackArg>>,
    /// List all available attacks.
    #[clap(long)]
    list: bool,
}

fn display_unciphered_data(uncipher: &Integer) {
    println!("Int = {uncipher}");
    println!("Hex = 0x{uncipher:02x}");
    if let Some(str) = integer_to_string(uncipher) {
        println!("String = \"{str}\"");
    } else {
        println!(
            "Bytes = b\"{}\"",
            display_bytes(&integer_to_bytes(uncipher))
        );
    }
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

    // Parse command line arguments
    let args = Args::parse();

    // List attacks
    if args.list {
        println!("Available attacks:");
        for attack in ATTACKS.iter() {
            println!("  {}", attack.name());
        }
        return Ok(());
    }

    // Read cipher
    let c = if args.cipher.is_some() {
        args.cipher.map(|n| n.0)
    } else if let Some(cipher_path) = args.cipherfile.as_ref() {
        match std::fs::read(cipher_path) {
            Ok(bytes) => Some(Integer::from_digits(&bytes, Order::Msf)),
            Err(err) => return Err(format!("{}: {err}", cipher_path.to_string_lossy()).into()),
        }
    } else {
        None
    };

    // Check if discrete logarithm can be computed
    if args.dlog && c.is_none() {
        return Err("Discrete logarithm requires a cipher".into());
    }

    // Build parameters
    let mut params = Parameters {
        c,
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

    // Read public and private keys
    if let Some(key) = args.key {
        let bytes = std::fs::read(key)?;

        params += Parameters::from_private_key(&bytes, args.password.as_deref())
            .or_else(|| Parameters::from_public_key(&bytes))
            .ok_or("Invalid key")?;
    };

    if args.dump {
        println!("{params}");
        return Ok(());
    }

    // Print public key
    if args.public {
        if let Some(n) = &params.n {
            let rsa = openssl::rsa::Rsa::from_public_components(
                openssl::bn::BigNum::from_slice(&n.to_digits(Order::Msf)).unwrap(),
                openssl::bn::BigNum::from_slice(&params.e.to_digits(Order::Msf)).unwrap(),
            )
            .or(Err("Invalid public key parameters"))?;
            let pem = rsa
                .public_key_to_pem()
                .map(|pem| String::from_utf8(pem).unwrap())
                .unwrap();
            print!("{pem}",);
            return Ok(());
        } else {
            return Err("No public key found".into());
        }
    }

    // Build attack list
    let attacks = args
        .attack
        // Collect attacks
        .map(|attacks| {
            attacks
                .into_iter()
                .map(|attack| attack.0)
                .collect::<Vec<_>>()
        })
        .unwrap_or(ATTACKS.to_vec())
        // Exclude attacks
        .into_iter()
        .filter(|attack| {
            args.exclude
                .as_ref()
                .map(|exclude| !exclude.iter().any(|a| a.0.name() == attack.name()))
                .unwrap_or(true)
        })
        // Sort attacks by kind and speed
        .sorted_by_key(|a| (a.kind(), a.speed()))
        .collect::<Vec<_>>();

    // Run attacks
    #[cfg(feature = "parallel")]
    let res = rsacracker::run_parallel_attacks(&params, &attacks, args.threads);
    #[cfg(not(feature = "parallel"))]
    let res = rsacracker::run_sequence_attacks(&params, &attacks);
    let solution = match res {
        Ok(solution) => solution,
        Err(partial_factors) => {
            // Print partial factors if any
            if let Some(partial_factors) = partial_factors {
                println!("Partial factors of n:");
                for (i, p) in partial_factors.as_vec().into_iter().enumerate() {
                    print!("p{} = {}", i + 1, p);
                    if p.is_probably_prime(100) != IsPrime::Yes {
                        print!(" (composite)");
                    }
                    println!();
                }
            }
            return Err("No attack succeeded".into());
        }
    };
    println!("Succeeded with attack: {}", solution.attack);

    // Print factors
    if args.factors {
        if let Some(private_key) = &solution.pk {
            println!("Factors of n:");
            if private_key.factors.len() == 2 {
                println!("p = {}", private_key.p());
                println!("q = {}", private_key.q());
            } else {
                for (i, p) in private_key.factors.as_vec().into_iter().enumerate() {
                    println!("p{} = {}", i + 1, p);
                }
            }
        } else {
            return Err("No private key found".into());
        }
        return Ok(());
    }

    // Print private key
    if args.private || args.dumpkey || args.dumpextkey {
        if let Some(private_key) = &solution.pk {
            if args.private {
                print!("{}", private_key.to_pem(&args.addpassword).unwrap());
            }
            if args.dumpkey || args.dumpextkey {
                println!("Private key:");
                println!("n = {}", private_key.n);
                println!("e = {}", private_key.e);

                // Print factors
                if private_key.factors.len() == 2 {
                    println!("p = {}", private_key.p());
                    println!("q = {}", private_key.q());
                } else {
                    for (i, p) in private_key.factors.as_vec().into_iter().enumerate() {
                        println!("p{} = {}", i + 1, p);
                    }
                }
                println!("d = {}", private_key.d);
            }
            if args.dumpextkey {
                println!("Extended private key:");
                println!("phi = {}", private_key.phi());
                println!("dP = {}", private_key.dp());
                println!("dQ = {}", private_key.dq());
                println!("pInv = {}", private_key.pinv());
                println!("qInv = {}", private_key.qinv());
            }
        } else {
            return Err("No private key found".into());
        }
        return Ok(());
    }

    // Print unciphered data
    if let Some(uncipher) = solution.m {
        println!("Unciphered data:");
        display_unciphered_data(&uncipher);

        // Print discrete logarithm
        if args.dlog {
            if let Some(pk) = &solution.pk {
                println!("Compute discrete logarithm...");
                if let Ok(dlog) = discrete_log_with_factors(
                    &pk.n,
                    &params.c.unwrap(),
                    &pk.e,
                    &pk.factors.to_hash_map(),
                ) {
                    display_unciphered_data(&dlog);
                } else {
                    return Err("Discrete logarithm failed".into());
                }
            } else {
                return Err("Discrete requires a private key".into());
            }
        }
    }

    // Print multiple unciphered data
    if !solution.ms.is_empty() {
        println!("Multiple unciphered data found:");
        for uncipher in solution.ms {
            println!();
            display_unciphered_data(&uncipher);
        }
    }

    Ok(())
}
