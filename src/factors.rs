use std::{
    collections::{BTreeMap, HashMap},
    ops::Index,
};

use rug::{ops::Pow, Integer};

/// Factors of a number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Factors(pub BTreeMap<Integer, usize>);

impl Factors {
    /// Returns the product of the factors.
    pub fn product(&self) -> Integer {
        self.0
            .iter()
            .map(|(f, p)| f.clone().pow(*p as u32))
            .product()
    }

    /// Returns the totient of the factors.
    pub fn phi(&self) -> Integer {
        self.0
            .iter()
            .map(|(f, p)| (f.clone() - 1u64).pow(*p as u32))
            .product()
    }

    /// Returns unique factors.
    pub fn factors(&self) -> Vec<&Integer> {
        self.0.keys().collect()
    }

    /// Returns the number of factors.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.0.values().sum()
    }

    /// Returns factors as a vector of references.
    pub fn as_vec(&self) -> Vec<&Integer> {
        self.0
            .iter()
            .flat_map(|(f, p)| std::iter::repeat(f).take(*p))
            .collect()
    }

    /// Returns factors as a vector.
    pub fn to_vec(&self) -> Vec<Integer> {
        self.0
            .iter()
            .flat_map(|(f, p)| std::iter::repeat(f.clone()).take(*p))
            .collect()
    }

    /// Returns factors as a hash map of references.
    pub fn as_hash_map(&self) -> HashMap<&Integer, usize> {
        self.0.iter().map(|(key, value)| (key, *value)).collect()
    }

    /// Returns factors as a hash map.
    pub fn to_hash_map(&self) -> HashMap<Integer, usize> {
        self.0.clone().into_iter().collect()
    }
}

impl Index<usize> for Factors {
    type Output = Integer;

    fn index(&self, index: usize) -> &Integer {
        let mut count = 0;
        for (factor, &factor_count) in self.0.iter() {
            count += factor_count;
            if count > index {
                return factor;
            }
        }
        panic!("Index out of bounds");
    }
}

impl From<BTreeMap<Integer, usize>> for Factors {
    fn from(factors: BTreeMap<Integer, usize>) -> Self {
        Self(factors)
    }
}

impl From<HashMap<Integer, usize>> for Factors {
    fn from(factors: HashMap<Integer, usize>) -> Self {
        Self(factors.into_iter().collect())
    }
}

impl From<&[Integer]> for Factors {
    fn from(factors: &[Integer]) -> Self {
        let mut map = HashMap::new();
        for factor in factors {
            *map.entry(factor.clone()).or_insert(0) += 1;
        }
        Self::from(map)
    }
}

impl<const N: usize> From<&[rug::Integer; N]> for Factors {
    fn from(factors: &[rug::Integer; N]) -> Self {
        Self::from(factors as &[rug::Integer])
    }
}
impl<const N: usize> From<[rug::Integer; N]> for Factors {
    fn from(factors: [rug::Integer; N]) -> Self {
        Self::from(&factors)
    }
}

impl From<Vec<Integer>> for Factors {
    fn from(factors: Vec<Integer>) -> Self {
        Self::from(factors.as_slice())
    }
}
