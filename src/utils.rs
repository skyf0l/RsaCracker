use rug::{ops::Pow, Integer};

/// Compute the log of n in given base, rounded up.
pub fn log_base_ceil(n: &Integer, base: usize) -> usize {
    if *n <= 1 {
        return 0;
    }

    let mut result = 0;
    let mut num = n.clone() - 1;

    while num > 0 {
        result += 1;
        num /= base;
    }

    result
}

/// Solve quadratic equation ax^2 + bx + c = 0 and return real integer solutions.
pub fn solve_quadratic(a: &Integer, b: &Integer, c: &Integer) -> Vec<Integer> {
    let delta = b.clone().pow(2) - Integer::from(4) * a * c;

    match delta {
        delta if delta == 0 => vec![-b.clone() / Integer::from(2 * a)],
        delta if delta > 0 => {
            let sqrt_delta = match delta.sqrt_rem(Integer::ZERO) {
                (sqrt_delta, rem) if rem == Integer::ZERO => sqrt_delta,
                _ => return vec![],
            };
            let x1 = (-b.clone() + &sqrt_delta) / (Integer::from(2) * a);
            let x2 = (-b.clone() - sqrt_delta) / (Integer::from(2) * a);
            vec![x1, x2]
        }
        _ => vec![],
    }
}
