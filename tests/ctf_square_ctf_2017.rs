use std::str::FromStr;

use rsacracker::{integer_to_string, run_attacks, KeyEntry, Parameters};
use rug::Integer;

#[test]
#[ignore] // TODO: Add correct values from the actual CTF challenge
fn square_ctf_2017_c1_gotta_decrypt_them_all() {
    // From Square CTF 2017 / C1: Gotta Decrypt Them All
    // https://ctftime.org/task/3973
    //
    // This is a multi-key RSA challenge where multiple public keys share common prime factors.
    // The attack uses GCD between different moduli to find common factors.
    //
    // Challenge format: Multiple RSA keys are provided, each encrypting part of the flag.
    // Strategy: Compute GCD(n1, n2), GCD(n1, n3), etc. to find common primes, then factor all keys.

    // Placeholder values - replace with actual challenge data
    let n1 = Integer::from_str("123456789").unwrap();
    let n2 = Integer::from_str("987654321").unwrap();
    let n3 = Integer::from_str("111222333").unwrap();
    
    let e = Integer::from(65537);
    
    let c1 = Integer::from_str("1000").unwrap();
    let c2 = Integer::from_str("2000").unwrap();
    let c3 = Integer::from_str("3000").unwrap();

    let params = Parameters {
        n: Some(n1.clone()),
        e: e.clone(),
        c: Some(c1),
        keys: vec![
            KeyEntry {
                n: Some(n2),
                e: e.clone(),
                c: Some(c2),
            },
            KeyEntry {
                n: Some(n3),
                e,
                c: Some(c3),
            },
        ],
        ..Default::default()
    };

    let solution = run_attacks(&params).unwrap();
    
    // The attack should succeed with common_factor or similar multi-key attack
    assert!(solution.pk.is_some() || solution.m.is_some());
    
    if let Some(m) = solution.m {
        let plaintext = integer_to_string(&m).unwrap();
        assert!(plaintext.contains("flag") || plaintext.len() > 0);
    }
}
