#![doc = include_str!("../README.md")]
#![deny(rust_2018_idioms)]
#![warn(missing_docs)]
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rug::integer::IsPrime;
use rug::Integer;
use std::cell::RefCell;
#[cfg(feature = "parallel")]
use std::sync::mpsc;
#[cfg(feature = "parallel")]
use std::sync::Arc;

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
pub fn run_attacks(params: &Parameters) -> Result<Solution, Option<Factors>> {
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
) -> Result<Solution, Option<Factors>> {
    #[cfg(feature = "parallel")]
    return run_parallel_attacks(params, attacks, num_cpus::get());
    #[cfg(not(feature = "parallel"))]
    run_sequence_attacks(params, attacks)
}

fn check_n_prime(n: &Option<Integer>) -> bool {
    if let Some(n) = &n {
        match n.is_probably_prime(100) {
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
            "{prefix:>12.bold} [{elapsed_precise}] {msg}[{wide_bar}] {pos}/{len:<4}",
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
) -> Result<Solution, Option<Factors>> {
    if check_n_prime(&params.n) {
        return Err(None);
    }

    let mut partial_factors: Option<Factors> = None;
    let (mp, pb_main) = create_multi_progress(attacks.len());
    for attack in attacks.iter() {
        match if attack.speed() == AttackSpeed::Fast {
            // No progress bar for fast attacks
            run_attack(attack.clone(), params, None)
        } else {
            let pb = create_progress_bar(&mp);
            run_attack(attack.clone(), params, Some(&pb))
        } {
            Ok(solution) => return Ok(solution),
            Err(Error::PartialFactorization(factor)) => {
                if let Some(partial_factors) = &mut partial_factors {
                    partial_factors.merge(&factor);
                } else {
                    partial_factors = Some(factor);
                }

                // Try to create a private key from the partial factors
                if let Ok(private_key) = PrivateKey::from_factors(
                    partial_factors.as_ref().unwrap().clone(),
                    params.e.clone(),
                ) {
                    return Ok(Solution::new_pk("Partial factors", private_key));
                }
                pb_main.set_message(format!(
                    "({} factors found) ",
                    partial_factors.as_ref().unwrap().len()
                ));
            }
            _ => {}
        }
        pb_main.inc(1);
    }

    Err(partial_factors)
}

#[cfg(feature = "parallel")]
async fn _run_parallel_attacks<'a>(
    params: Arc<Parameters>,
    attacks: &[Arc<dyn Attack + Sync + Send>],
    sender: mpsc::Sender<Result<Solution, Error>>,
    mp: Arc<MultiProgress>,
) {
    // Create all progress bars
    let pbs = RefCell::new(Vec::with_capacity(attacks.len()));
    for _ in 0..attacks.len() {
        pbs.borrow_mut().push(Arc::new(create_progress_bar(&mp)));
    }

    for (attack, pb) in attacks.iter().cloned().zip(pbs.borrow().iter().cloned()) {
        // Clone variables for closure
        let params = Arc::clone(&params);
        let sender = sender.clone();
        let mp = Arc::clone(&mp);
        let pbs = RefCell::clone(&pbs);

        // Spawn attack as a task
        tokio::task::spawn(async move {
            let res = run_attack(attack, &params, Some(&pb));

            // Remove progress bar from list
            mp.remove(&pb);
            // If attack was successful, clear all progress bars
            if res.is_ok() {
                for pb in pbs.borrow().iter() {
                    pb.finish_and_clear();
                }
            }

            // Send result to main thread
            // Note: error if channel closed
            sender.send(res).ok();
        });
    }
}

/// Run all attacks in parallel, from fastest to slowest (multi-threaded)
#[cfg(feature = "parallel")]
pub fn run_parallel_attacks(
    params: &Parameters,
    attacks: &[Arc<dyn Attack + Sync + Send>],
    threads: usize,
) -> Result<Solution, Option<Factors>> {
    if check_n_prime(&params.n) {
        return Err(None);
    }

    if threads <= 1 {
        return run_sequence_attacks(params, attacks);
    }

    // User for key build from partial factors
    let param_e = params.e.clone();

    // Create channel for sending result
    let (sender, receiver) = mpsc::channel();

    // Create progress bar
    let (mp, pb_main) = create_multi_progress(attacks.len());

    // Create runtime
    let params = Arc::new(params.clone());
    let r = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
        .unwrap();

    // Spawn attacks in background
    let attacks = attacks.to_vec();
    r.spawn(async move { _run_parallel_attacks(params, &attacks, sender, mp).await });

    // Retrieve result
    let mut partial_factors: Option<Factors> = None;
    let solution = loop {
        // Receive solution or error for each attack
        match receiver.recv() {
            Ok(Ok(solution)) => break Some(solution),
            Ok(Err(Error::PartialFactorization(factor))) => {
                if let Some(partial_factors) = &mut partial_factors {
                    partial_factors.merge(&factor);
                } else {
                    partial_factors = Some(factor);
                }

                // Try to create a private key from the partial factors
                if let Ok(private_key) = PrivateKey::from_factors(
                    partial_factors.as_ref().unwrap().clone(),
                    param_e.clone(),
                ) {
                    break Some(Solution::new_pk("Partial factors", private_key));
                }
                pb_main.set_message(format!(
                    "({} factors found) ",
                    partial_factors.as_ref().unwrap().len()
                ));
            }
            Ok(_) => {}
            Err(_) => {
                // Channel closed, no more results available
                break None;
            }
        }

        // Update progress bar
        pb_main.inc(1);
    };

    // Shut down runtime
    r.shutdown_background();
    eprintln!("Elapsed time: {:?}", pb_main.elapsed());

    if let Some(solution) = solution {
        Ok(solution)
    } else {
        Err(partial_factors)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, str::FromStr};

    use rug::ops::Pow;

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

    #[test]
    fn partial_factors() {
        // n == 2 ^ 63 * 690712633549859897233 ^ 6
        let p = Integer::from(690712633549859897233u128);
        let params = Parameters {
            n: Some(Integer::from(2).pow(63) * p.clone().pow(5)),
            ..Default::default()
        };

        let err = run_specific_attacks(&params, &[Arc::new(SmallPrimeAttack)]).unwrap_err();
        let partial_factors = err.unwrap();
        assert_eq!(
            partial_factors.0,
            BTreeMap::from([(Integer::from(2), 63), (p.pow(5), 1),])
        );
    }
}
