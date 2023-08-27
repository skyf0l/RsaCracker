#![doc = include_str!("../README.md")]
#![deny(rust_2018_idioms)]
#![warn(missing_docs)]
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use itertools::Itertools;
use rug::integer::IsPrime;
use rug::Integer;
#[cfg(feature = "parallel")]
use std::sync::mpsc;
#[cfg(feature = "parallel")]
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

mod attack;
mod factors;
mod key;
mod ntheory;
mod params;
mod solution;
mod utils;

pub use attack::*;
pub use factors::*;
pub use key::*;
pub use params::*;
pub use solution::*;

/// Convert a `rug::Integer` to a byte vector.
pub fn integer_to_bytes(i: &Integer) -> Vec<u8> {
    base_x::decode("0123456789", &i.to_string()).unwrap()
}

/// Convert a `rug::Integer` to a string.
pub fn integer_to_string(i: &Integer) -> Option<String> {
    String::from_utf8(integer_to_bytes(i)).ok()
}

/// Convert a byte vector to a `rug::Integer`.
pub fn bytes_to_integer(bytes: &[u8]) -> Integer {
    Integer::from_str_radix(&base_x::encode("0123456789", bytes), 10).unwrap()
}

/// Convert a string to a `rug::Integer`.
pub fn string_to_integer(s: &str) -> Integer {
    bytes_to_integer(s.as_bytes())
}

/// Run a single attack.
pub fn run_attack(
    attack: Arc<dyn Attack + Sync + Send>,
    params: &Parameters,
    pb: Option<&ProgressBar>,
) -> Result<Solution, Error> {
    if let Some(pb) = pb {
        pb.set_prefix(attack.name());
    }

    let mut solution = attack.run(params, pb)?;
    // Try to decrypt the cipher if no message was found
    if let (Some(pk), None, Some(c)) = (&solution.pk, &solution.m, &params.c) {
        solution.m = Some(pk.decrypt(c))
    }

    Ok(solution)
}

/// Run all attacks.
///
/// When the `parallel` feature is enabled, this function will run all attacks in parallel using all available CPU cores.
/// Else, it will run all attacks in sequence (single-threaded).
pub fn run_attacks(params: &Parameters) -> Result<Solution, Option<Vec<Factors>>> {
    #[cfg(feature = "parallel")]
    return run_parallel_attacks(params, &ATTACKS, num_cpus::get());
    #[cfg(not(feature = "parallel"))]
    run_sequence_attacks(params, &ATTACKS)
}

/// Run specific attacks.
///
/// When the `parallel` feature is enabled, this function will run all attacks in parallel using all available CPU cores.
/// Else, it will run all attacks in sequence (single-threaded).
pub fn run_specific_attacks(
    params: &Parameters,
    attacks: &[Arc<dyn Attack + Sync + Send>],
) -> Result<Solution, Option<Vec<Factors>>> {
    #[cfg(feature = "parallel")]
    return run_parallel_attacks(params, attacks, num_cpus::get());
    #[cfg(not(feature = "parallel"))]
    run_sequence_attacks(params, attacks)
}

fn check_n_prime(n: &Option<Integer>) -> bool {
    if let Some(n) = &n {
        match n.is_probably_prime(30) {
            IsPrime::Yes => {
                eprintln!("Error: N is prime, no attacks possible");
                return true;
            }
            IsPrime::Probably => {
                eprintln!("Warning: n is probably prime, but not certain");
            }
            _ => {}
        }
    }
    false
}

fn create_multi_progress(nb_attacks: usize) -> (Arc<MultiProgress>, Arc<ProgressBar>) {
    let mp = Arc::new(MultiProgress::new());
    let pb_main = Arc::new(mp.add(ProgressBar::new(nb_attacks as u64)));

    pb_main.set_style(
        ProgressStyle::with_template(
            "{prefix:>12.bold} [{elapsed_precise}] [{wide_bar}] {pos}/{len:<4}",
        )
        .unwrap()
        .progress_chars("=> "),
    );
    pb_main.set_prefix("Running");
    (mp, pb_main)
}

fn create_progress_bar(mp: &MultiProgress) -> ProgressBar {
    let pb = mp.insert(0, ProgressBar::new(1));
    pb.set_style(
        ProgressStyle::with_template(
            "{prefix:>12.bold} [{elapsed_precise}] [{wide_bar}] {percent:>3}% ({eta:^4}) ",
        )
        .unwrap(),
    );
    pb
}

/// Run all attacks in sequence, from fastest to slowest (single-threaded)
pub fn run_sequence_attacks(
    params: &Parameters,
    attacks: &[Arc<dyn Attack + Sync + Send>],
) -> Result<Solution, Option<Vec<Factors>>> {
    if check_n_prime(&params.n) {
        return Err(None);
    }

    let mut partial_factors = Vec::new();
    let (mp, pb_main) = create_multi_progress(attacks.len());
    for attack in attacks.iter().sorted_by_key(|a| a.speed()) {
        match if attack.speed() == AttackSpeed::Fast {
            // No progress bar for fast attacks
            run_attack(attack.clone(), params, None)
        } else {
            let pb = create_progress_bar(&mp);
            run_attack(attack.clone(), params, Some(&pb))
        } {
            Ok(solution) => return Ok(solution),
            Err(Error::PartialFactorization(factor)) => {
                partial_factors.push(factor);
            }
            _ => {}
        }
        pb_main.inc(1);
    }

    if !partial_factors.is_empty() {
        Err(Some(partial_factors))
    } else {
        Err(None)
    }
}

#[cfg(feature = "parallel")]
async fn _run_parallel_attacks<'a>(
    params: Arc<Parameters>,
    attacks: &[Arc<dyn Attack + Sync + Send>],
    sender: mpsc::Sender<Result<Solution, Error>>,
) {
    let (mp, pb_main) = create_multi_progress(attacks.len());

    for attack in attacks.iter().sorted_by_key(|a| a.speed()) {
        let params = Arc::clone(&params);
        let attack = Arc::clone(attack);
        let sender = sender.clone();
        let mp = Arc::clone(&mp);
        let pb_main = Arc::clone(&pb_main);
        tokio::task::spawn(async move {
            match if attack.speed() == AttackSpeed::Fast {
                // No progress bar for fast attacks
                run_attack(attack, &params, None)
            } else {
                let pb = create_progress_bar(&mp);
                run_attack(attack, &params, Some(&pb))
            } {
                Ok(solution) => {
                    mp.suspend(|| {
                        sender.send(Ok(solution)).expect("Failed to send result");
                        // This is a hack to make sure the progress bar is not displayed after the attack is done
                        sleep(Duration::from_millis(1000));
                    });
                }
                e => sender.send(e).expect("Failed to send result"),
            }
            pb_main.inc(1);
        });
    }
}

/// Run all attacks in parallel, from fastest to slowest (multi-threaded)
#[cfg(feature = "parallel")]
pub fn run_parallel_attacks(
    params: &Parameters,
    attacks: &[Arc<dyn Attack + Sync + Send>],
    threads: usize,
) -> Result<Solution, Option<Vec<Factors>>> {
    if check_n_prime(&params.n) {
        return Err(None);
    }

    if threads <= 1 {
        return run_sequence_attacks(params, attacks);
    }

    // Create channel for sending result
    let (sender, receiver) = mpsc::channel();

    // Create runtime
    let params = Arc::new(params.clone());
    let r = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
        .unwrap();

    // Spawn attacks in background
    let attacks = attacks.to_vec();
    r.spawn(async move { _run_parallel_attacks(params, &attacks, sender).await });

    // Retrieve result
    let mut partial_factors = Vec::new();
    let solution = loop {
        match receiver.recv() {
            Ok(Ok(solution)) => break Some(solution),
            Ok(Err(Error::PartialFactorization(factor))) => {
                partial_factors.push(factor);
            }
            Ok(_) => {}
            Err(_) => {
                // Channel closed, no more results available
                break None;
            }
        }
    };

    // Shut down runtime
    r.shutdown_background();

    if let Some(solution) = solution {
        Ok(solution)
    } else if !partial_factors.is_empty() {
        Err(Some(partial_factors))
    } else {
        Err(None)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn small_n_prime() {
        let params = Parameters {
            n: Some(17.into()),
            ..Default::default()
        };

        assert!(run_attacks(&params).is_err());
    }

    #[test]
    fn medium_n_prime() {
        let params = Parameters {
            n: Some(Integer::from_str("220375572875274133043506876099").unwrap()),
            ..Default::default()
        };

        assert!(run_attacks(&params).is_err());
    }
}
