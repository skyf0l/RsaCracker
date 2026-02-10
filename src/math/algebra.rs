//! Algebraic operations and mathematical functions.
//!
//! Provides general algebraic operations used in cryptographic attacks,
//! including equation solving and logarithmic calculations.

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
        delta if delta == 0 => vec![-b.clone() / (Integer::from(2) * a)],
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_base_ceil() {
        assert_eq!(log_base_ceil(&Integer::from(1), 2), 0);
        assert_eq!(log_base_ceil(&Integer::from(2), 2), 1);
        assert_eq!(log_base_ceil(&Integer::from(3), 2), 2);
        assert_eq!(log_base_ceil(&Integer::from(4), 2), 2);
        assert_eq!(log_base_ceil(&Integer::from(8), 2), 3);
        assert_eq!(log_base_ceil(&Integer::from(9), 2), 4);
    }

    #[test]
    fn test_solve_quadratic() {
        // x^2 - 5x + 6 = 0, solutions: x = 2, 3
        let solutions = solve_quadratic(&Integer::from(1), &Integer::from(-5), &Integer::from(6));
        assert_eq!(solutions.len(), 2);
        assert!(solutions.contains(&Integer::from(2)));
        assert!(solutions.contains(&Integer::from(3)));

        // x^2 - 4x + 4 = 0, solution: x = 2 (double root)
        let solutions = solve_quadratic(&Integer::from(1), &Integer::from(-4), &Integer::from(4));
        assert_eq!(solutions, vec![Integer::from(2)]);

        // x^2 + 1 = 0, no real solutions
        let solutions = solve_quadratic(&Integer::from(1), &Integer::from(0), &Integer::from(1));
        assert_eq!(solutions.len(), 0);
    }
}
