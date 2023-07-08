#![doc = include_str!("../README.md")]
#![deny(rust_2018_idioms)]
#![warn(missing_docs)]
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rug::integer::IsPrime;
use rug::Integer;
#[cfg(feature = "parallel")]
use std::sync::mpsc;
#[cfg(feature = "parallel")]
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

mod attack;
mod key;
mod ntheory;
mod params;
mod solution;
mod utils;

pub use attack::*;
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
#[allow(clippy::borrowed_box)]
pub fn run_attack(
    attack: &Box<dyn Attack + Sync>,
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
pub fn run_attacks(params: &Parameters) -> Option<Solution> {
    #[cfg(feature = "parallel")]
    return run_parallel_attacks(params, num_cpus::get());
    #[cfg(not(feature = "parallel"))]
    run_sequence_attacks(params)
}

fn check_n_prime(n: &Option<Integer>) -> Option<()> {
    if let Some(n) = &n {
        match n.is_probably_prime(30) {
            IsPrime::Yes => {
                eprintln!("Error: N is prime, no attacks possible");
                return None;
            }
            IsPrime::Probably => {
                eprintln!("Warning: n is probably prime, but not certain");
            }
            _ => {}
        }
    }
    Some(())
}

fn create_multi_progress() -> (Arc<MultiProgress>, Arc<ProgressBar>) {
    let mp = Arc::new(MultiProgress::new());
    let pb_main = Arc::new(mp.add(ProgressBar::new(ATTACKS.len() as u64)));

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

/// Run all attacks in sequence (single-threaded)
pub fn run_sequence_attacks(params: &Parameters) -> Option<Solution> {
    check_n_prime(&params.n)?;

    let (mp, pb_main) = create_multi_progress();
    for attack in ATTACKS.iter() {
        let pb = create_progress_bar(&mp);
        if let Ok(solved) = run_attack(attack, params, Some(&pb)) {
            return Some(solved);
        }
        pb_main.inc(1);
    }
    None
}

#[cfg(feature = "parallel")]
async fn _run_parallel_attacks(params: Arc<Parameters>, sender: mpsc::Sender<Solution>) {
    let (mp, pb_main) = create_multi_progress();

    for attack in ATTACKS.iter() {
        let params = Arc::clone(&params);
        let sender = sender.clone();
        let mp = Arc::clone(&mp);
        let pb_main = Arc::clone(&pb_main);
        tokio::task::spawn(async move {
            let pb = create_progress_bar(&mp);
            if let Ok(solved) = run_attack(attack, &params, Some(&pb)) {
                mp.suspend(|| {
                    sender.send(solved).expect("Failed to send result");
                    // This is a hack to make sure the progress bar is not displayed after the attack is done
                    sleep(Duration::from_millis(1000));
                });
            }
            pb_main.inc(1);
        });
    }
}

/// Run all attacks in parallel (multi-threaded)
#[cfg(feature = "parallel")]
pub fn run_parallel_attacks(params: &Parameters, threads: usize) -> Option<Solution> {
    if threads <= 1 {
        return run_sequence_attacks(params);
    }

    check_n_prime(&params.n)?;

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
    r.spawn(async { _run_parallel_attacks(params, sender).await });

    // Wait for result
    let res = receiver.recv().ok();

    // Shut down runtime
    r.shutdown_background();

    res
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

        assert!(run_attacks(&params).is_none());
    }

    #[test]
    fn huge_n_prime() {
        let params = Parameters {
            n: Some(Integer::from_str("3422439879021862741231658874852020811369429686198702457924807491341988797025050611590032128268794011").unwrap()),  
            ..Default::default()
        };

        assert!(run_attacks(&params).is_none());
    }
}
