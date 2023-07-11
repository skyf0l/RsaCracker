use rug::Integer;

use crate::key::PrivateKey;

/// Attack's result
#[derive(Debug, Clone)]
pub struct Solution {
    /// Attack's name
    pub attack: &'static str,
    /// The private key
    pub pk: Option<PrivateKey>,
    /// The decrypted message
    pub m: Option<Integer>,
    /// Possible decrypted messages
    pub ms: Vec<Integer>,
}

impl Solution {
    /// Create a new solution
    pub fn new(attack: &'static str, pk: PrivateKey, m: Integer) -> Self {
        Self {
            attack,
            pk: Some(pk),
            m: Some(m),
            ms: vec![],
        }
    }

    /// Create a new solution with only the private key
    pub fn new_pk(attack: &'static str, pk: PrivateKey) -> Self {
        Self {
            attack,
            pk: Some(pk),
            m: None,
            ms: vec![],
        }
    }

    /// Create a new solution with only the decrypted message
    pub fn new_m(attack: &'static str, m: Integer) -> Self {
        Self {
            attack,
            pk: None,
            m: Some(m),
            ms: vec![],
        }
    }

    /// Create a new solution with only the possible decrypted messages
    pub fn new_ms(attack: &'static str, ms: Vec<Integer>) -> Self {
        Self {
            attack,
            pk: None,
            m: None,
            ms,
        }
    }
}
