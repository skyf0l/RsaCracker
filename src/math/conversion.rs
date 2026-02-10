//! Type conversion utilities for cryptographic data.

use rug::Integer;

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

    #[test]
    fn round_trip_conversions() {
        let original = "Hello, RSA!";
        let integer = string_to_integer(original);
        let converted_back = integer_to_string(&integer).unwrap();
        assert_eq!(original, converted_back);

        let bytes = original.as_bytes();
        let int_from_bytes = bytes_to_integer(bytes);
        let bytes_back = integer_to_bytes(&int_from_bytes);
        assert_eq!(bytes, bytes_back.as_slice());
    }
}
