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

    /// Optimizes factors when some are divisible by others.
    pub fn optimize(&mut self) {
        self.merge(&self.clone());
    }

    /// Merges two factors of the same number into one.
    /// The result is the union of the two factors.
    pub fn merge(&mut self, other: &Self) {
        if self.product() != other.product() {
            panic!("Factors must be of the same number");
        }

        for other_factor in other.0.keys().rev() {
            // let mut apply = None;

            for origin_factor in self.0.keys() {
                // Skip if the divisor is greater than the dividend.
                if origin_factor <= other_factor {
                    continue;
                }

                // If divisible, merge them.
                if origin_factor.is_divisible(other_factor) {
                    // Calculate the number of times the divisor can be divided by the dividend.
                    let mut count = 0;
                    let mut rem = origin_factor.clone();
                    while rem.is_divisible(other_factor) {
                        rem /= other_factor.clone();
                        count += 1;
                    }

                    // Update the factors.
                    let origin_count = self.0.remove(&origin_factor.clone()).unwrap();
                    *self.0.entry(other_factor.clone()).or_insert(0) += count * origin_count;
                    if rem != 1 {
                        *self.0.entry(rem).or_insert(0) += origin_count;
                    }

                    break;
                }
            }
        }
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
        let mut factors = Self(factors);

        factors.optimize();
        factors
    }
}

impl From<HashMap<Integer, usize>> for Factors {
    fn from(factors: HashMap<Integer, usize>) -> Self {
        Self::from(factors.into_iter().collect::<BTreeMap<_, _>>())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optimize_1() {
        let mut factors = Factors::from(HashMap::from([(2.into(), 3), (8.into(), 9)]));

        factors.optimize();
        assert_eq!(factors, Factors::from(HashMap::from([(2.into(), 30)])));
    }

    #[test]
    fn optimize_2() {
        let mut factors =
            Factors::from(HashMap::from([(2.into(), 1), (4.into(), 1), (8.into(), 9)]));

        factors.optimize();
        assert_eq!(factors, Factors::from(HashMap::from([(2.into(), 30)])));
    }

    #[test]
    fn merge() {
        let mut factors = Factors::from([30555.into()]);

        factors.merge(&Factors::from([5.into(), 6111.into()]));
        assert_eq!(factors, Factors::from([5.into(), 6111.into()]));
        factors.merge(&Factors::from([7.into(), 4365.into()]));
        assert_eq!(factors, Factors::from([5.into(), 7.into(), 873.into()]));
        factors.merge(&Factors::from([3.into(), 7.into(), 1455.into()]));
        assert_eq!(
            factors,
            Factors::from([3.into(), 3.into(), 5.into(), 7.into(), 97.into()])
        );
        factors.merge(&Factors::from([
            3.into(),
            3.into(),
            5.into(),
            7.into(),
            97.into(),
        ]));
        assert_eq!(
            factors,
            Factors::from([3.into(), 3.into(), 5.into(), 7.into(), 97.into()])
        );
    }

    #[test]
    fn multiple_merge_1() {
        let mut factors = Factors::from(HashMap::from([(8.into(), 10)]));

        factors.merge(&Factors::from(HashMap::from([
            (2.into(), 3),
            (8.into(), 9),
        ])));
        assert_eq!(factors, Factors::from(HashMap::from([(2.into(), 30)])));
    }

    #[test]
    fn multiple_merge_2() {
        let mut factors = Factors::from(HashMap::from([(8.into(), 10)]));

        factors.merge(&Factors::from(HashMap::from([
            (2.into(), 1),
            (4.into(), 1),
            (8.into(), 9),
        ])));
        assert_eq!(factors, Factors::from(HashMap::from([(2.into(), 30)])));
    }
}
