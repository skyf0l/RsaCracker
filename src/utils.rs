use rug::{ops::Pow, Integer};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_to_integer_to_bytes() {
        let bytes = b"RsaCracker!";
        assert_eq!(bytes, integer_to_bytes(&bytes_to_integer(bytes)).as_slice());
    }

    #[test]
    fn string_to_integer_to_string() {
        let str = "RsaCracker!";
        assert_eq!(str, integer_to_string(&string_to_integer(str)).unwrap());
    }
}
