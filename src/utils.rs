use rug::{ops::Pow, Integer};

/// Compute the Euler's totient.
pub fn phi(factors: &[Integer]) -> Integer {
    let mut phi = Integer::from(1);

    for p in factors {
        phi *= p - Integer::from(1);
    }
    phi
}

/// Solve quadratic equation ax^2 + bx + c = 0 and return real solutions.
pub fn solve_quadratic(a: &Integer, b: &Integer, c: &Integer) -> Vec<Integer> {
    let delta = b.clone().pow(2) - Integer::from(4) * a * c;

    match delta {
        delta if delta == 0 => vec![-b.clone() / Integer::from(2 * a)],
        delta if delta > 0 => {
            let sqrt_delta = delta.sqrt();
            let x1 = (-b.clone() + &sqrt_delta) / (Integer::from(2) * a);
            let x2 = (-b.clone() - sqrt_delta) / (Integer::from(2) * a);
            vec![x1, x2]
        }
        _ => vec![],
    }
}
