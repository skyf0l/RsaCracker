use rug::Integer;

use crate::key::PrivateKey;

/// Attack's result
#[derive(Debug, Clone)]
pub struct Solution {
    /// The private key
    pub pk: Option<PrivateKey>,
    /// The decrypted message
    pub m: Option<Integer>,
    /// Possible decrypted messages
    pub ms: Vec<Integer>,
}

impl Solution {
    /// Create a new solution
    pub fn new(pk: PrivateKey, m: Integer) -> Self {
        Self {
            pk: Some(pk),
            m: Some(m),
            ms: vec![],
        }
    }

    /// Create a new solution with only the private key
    pub fn new_pk(pk: PrivateKey) -> Self {
        Self {
            pk: Some(pk),
            m: None,
            ms: vec![],
        }
    }

    /// Create a new solution with only the decrypted message
    pub fn new_m(m: Integer) -> Self {
        Self {
            pk: None,
            m: Some(m),
            ms: vec![],
        }
    }

    /// Create a new solution with only the possible decrypted messages
    pub fn new_ms(ms: Vec<Integer>) -> Self {
        Self {
            pk: None,
            m: None,
            ms,
        }
    }
}
