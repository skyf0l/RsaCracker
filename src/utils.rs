use rug::Integer;

/// Compute the Euler's totient.
pub fn phi(factors: &[Integer]) -> Integer {
    let mut phi = Integer::from(1);

    for p in factors {
        phi *= p - Integer::from(1);
    }
    phi
}
