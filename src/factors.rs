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

    /// Returns the Euler totient of the factors.
    ///
    /// Note:
    /// - phi(a*b) = phi(a) * phi(b)
    /// - phi(p^k) = (p-1) * p^(k-1)
    pub fn phi(&self) -> Integer {
        self.phis().into_iter().product()
    }

    /// Returns the Euler totient of each unique factor (phi(p^k)).
    pub fn phis(&self) -> Vec<Integer> {
        self.0
            .iter()
            .map(|(f, p)| (f.clone()).pow(*p as u32 - 1u32) * (f.clone() - 1))
            .collect()
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

impl<T: Clone + Into<Integer>> From<BTreeMap<T, usize>> for Factors {
    fn from(factors: BTreeMap<T, usize>) -> Self {
        let factors = factors.into_iter().map(|(k, v)| (k.into(), v)).collect();
        let mut factors = Self(factors);

        factors.optimize();
        factors
    }
}

impl<T: Clone + Into<Integer> + Ord> From<HashMap<T, usize>> for Factors {
    fn from(factors: HashMap<T, usize>) -> Self {
        Self::from(factors.into_iter().collect::<BTreeMap<_, _>>())
    }
}

impl<T: Clone + Into<Integer>> From<&[T]> for Factors {
    fn from(factors: &[T]) -> Self {
        let mut map = HashMap::new();
        for factor in factors {
            *map.entry(factor.clone().into()).or_insert(0) += 1;
        }
        Self::from(map)
    }
}

impl<T: Clone + Into<Integer>, const N: usize> From<&[T; N]> for Factors {
    fn from(factors: &[T; N]) -> Self {
        Self::from(factors as &[T])
    }
}

impl<T: Clone + Into<Integer>, const N: usize> From<[T; N]> for Factors {
    fn from(factors: [T; N]) -> Self {
        Self::from(&factors)
    }
}

impl<T: Clone + Into<Integer>> From<Vec<T>> for Factors {
    fn from(factors: Vec<T>) -> Self {
        Self::from(factors.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn product_and_phi() {
        let p = Integer::from_str("11106026672819778415395265319351312104517763207376765038636473714941732117831488482730793398782365364840624898218935983446211558033147834146885518313145941").unwrap();
        let q = Integer::from_str("12793494802119353329493630005275969260540058187994460635179617401018719587481122947567147790680079651999077966705114757935833094909655872125005398075725409").unwrap();

        let factors = Factors::from([p.clone(), q.clone()]);

        assert_eq!(factors.product(), p.clone() * &q);
        assert_eq!(factors.phi(), (p - 1) * (q - 1));
    }

    #[test]
    fn multiple_primes_product_and_phi() {
        let p = Integer::from_str("10193015828669388212171268316396616412166866643440710733674534917491644123135436050477232002188857603479321547506131679866357093667445348339711929671105733").unwrap();
        let q = Integer::from_str("8826244874397589965592244959402585690675974843434609869757034692220480232437419549416634170391846191239385439228177059214900435042874545573920364227747261").unwrap();
        let r = Integer::from_str("7352042777909126576764043061995108196815011736073183321111078742728938275060552442022686305342309076279692633229512445674423158310200668776459828180575601").unwrap();
        let s = Integer::from_str("9118676262959556930818956921827413198986277995127667203870694452397233225961924996910197904901037135372560207618442015208042298428698343225720163505153059").unwrap();

        let factors = Factors::from([p.clone(), q.clone(), r.clone(), s.clone()]);

        assert_eq!(factors.product(), p.clone() * &q * &r * &s);
        assert_eq!(factors.phi(), (p - 1) * (q - 1) * (r - 1) * (s - 1));
    }

    #[test]
    fn optimize_1() {
        let mut factors = Factors::from(HashMap::from([(2, 3), (8, 9)]));

        factors.optimize();
        assert_eq!(factors, Factors::from(HashMap::from([(2, 30)])));
    }

    #[test]
    fn optimize_2() {
        let mut factors = Factors::from(HashMap::from([(2, 1), (4, 1), (8, 9)]));

        factors.optimize();
        assert_eq!(factors, Factors::from(HashMap::from([(2, 30)])));
    }

    #[test]
    fn merge() {
        let mut factors = Factors::from([30555]);

        factors.merge(&Factors::from([5, 6111]));
        assert_eq!(factors, Factors::from([5, 6111]));
        factors.merge(&Factors::from([7, 4365]));
        assert_eq!(factors, Factors::from([5, 7, 873]));
        factors.merge(&Factors::from([3, 7, 1455]));
        assert_eq!(factors, Factors::from([3, 3, 5, 7, 97]));
        factors.merge(&Factors::from([3, 3, 5, 7, 97]));
        assert_eq!(factors, Factors::from([3, 3, 5, 7, 97]));
    }

    #[test]
    fn multiple_merge_1() {
        let mut factors = Factors::from(HashMap::from([(8, 10)]));

        factors.merge(&Factors::from(HashMap::from([(2, 3), (8, 9)])));
        assert_eq!(factors, Factors::from(HashMap::from([(2, 30)])));
    }

    #[test]
    fn multiple_merge_2() {
        let mut factors = Factors::from(HashMap::from([(8, 10)]));

        factors.merge(&Factors::from(HashMap::from([(2, 1), (4, 1), (8, 9)])));
        assert_eq!(factors, Factors::from(HashMap::from([(2, 30)])));
    }
}
