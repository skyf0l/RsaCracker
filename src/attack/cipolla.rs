use indicatif::ProgressBar;
use rug::{integer::IsPrime, Integer};

use crate::{
    math::field::{PrimeField, QuadraticExtension},
    Attack, AttackKind, Error, Parameters, Solution,
};

const MAX_ITERATIONS: u64 = 1_000_000;
const TICK_SIZE: u64 = MAX_ITERATIONS / 100;

/// Check if x is a quadratic residue modulo p using Euler's criterion
/// Returns true if x^((p-1)/2) ≡ 1 (mod p)
fn is_quadratic_residue(x: &Integer, p: &Integer) -> bool {
    if x == &0 {
        return true;
    }
    let exp = (p.clone() - 1) >> 1;
    x.clone().pow_mod(&exp, p).unwrap() == 1
}

/// Cipolla's algorithm for finding square roots modulo a prime.
///
/// Uses the shared PrimeField and QuadraticExtension abstractions for clean,
/// maintainable field arithmetic.
///
/// Given a and p (odd prime), finds x such that x^2 ≡ a (mod p)
/// Returns both solutions (x, p-x) if they exist, None if a is not a quadratic residue
///
/// Algorithm:
/// 1. Find r such that r^2 - a is a quadratic non-residue mod p
/// 2. Work in the extension field F_p[x]/(x^2 - omega) where omega = r^2 - a
/// 3. Compute (r + x)^((p+1)/2) to obtain the square root
///
/// Time complexity: O(log p) field operations in the extension
/// Reference: Cipolla (1903)
pub fn cipolla(a: &Integer, p: &Integer, pb: Option<&ProgressBar>) -> Option<(Integer, Integer)> {
    let a = a.clone() % p;

    // Special cases
    if a == 0 || a == 1 {
        return Some((a.clone(), (p.clone() - &a) % p));
    }

    // Check if a is a quadratic residue using Euler's criterion
    if !is_quadratic_residue(&a, p) {
        return None;
    }

    if let Some(pb) = pb {
        pb.set_length(MAX_ITERATIONS);
    }

    // Find r such that omega = r^2 - a is a non-residue
    let mut r = Integer::from(1);
    let omega_int;
    loop {
        let r_squared = r.clone() * &r;
        let mut candidate = (r_squared - &a) % p;
        if candidate < 0 {
            candidate += p;
        }

        if !is_quadratic_residue(&candidate, p) {
            omega_int = candidate;
            break;
        }

        r += 1;

        let r_mod = Integer::from(&r % TICK_SIZE);
        if r_mod == 0 {
            if let Some(pb) = pb {
                pb.inc(TICK_SIZE);
            }
        }

        if r > MAX_ITERATIONS {
            // Failed to find non-residue (extremely rare for random search)
            return None;
        }
    }

    // Create base field and extension field
    let field = PrimeField::new(p.clone());

    // Construct element (r + x) in F_p[x]/(x^2 - omega)
    let element = QuadraticExtension::new(&field, r, Integer::from(1), omega_int);

    // Compute (r + x)^((p+1)/2) using fast exponentiation
    let exp = (p.clone() + 1) >> 1;
    let result = element.pow(&exp);

    // Extract result - the imaginary part should be 0 for a valid square root
    let x0 = result.real().clone();
    let x1 = (p.clone() - &x0) % p;

    // Return in sorted order (smaller first)
    if x0 < x1 {
        Some((x0, x1))
    } else {
        Some((x1, x0))
    }
}

/// Cipolla's algorithm attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CipollaAttack;

impl Attack for CipollaAttack {
    fn name(&self) -> &'static str {
        "cipolla"
    }

    fn kind(&self) -> AttackKind {
        AttackKind::KnownExtraInformation
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;
        let c = params.c.as_ref().ok_or(Error::MissingParameters)?;
        if n.is_probably_prime(100) == IsPrime::No {
            // N should be prime
            return Err(Error::NotFound);
        }

        let phi = Integer::from(n - 1);
        let d = Integer::from(e / 2)
            .invert(&(phi / 2))
            .or(Err(Error::NotFound))?;
        let m = c.clone().pow_mod(&d, n).unwrap();
        let (m1, m2) = cipolla(&m, n, pb).ok_or(Error::NotFound)?;

        Ok(Solution::new_ms(self.name(), vec![m1, m2]))
    }
}
#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{string_to_integer, Attack, Parameters};

    use super::*;

    #[test]
    fn cipolla_small_numbers() {
        assert_eq!(
            cipolla(&1.into(), &43.into(), None),
            Some((1.into(), 42.into()))
        );
        assert_eq!(
            cipolla(&2.into(), &23.into(), None),
            Some((5.into(), 18.into()))
        );
        assert_eq!(
            cipolla(&17.into(), &83.into(), None),
            Some((10.into(), 73.into()))
        );
    }

    #[test]
    fn cipolla_random_numbers() {
        assert_eq!(
            cipolla(&392203.into(), &852167.into(), None),
            Some((413252.into(), 438915.into()))
        );
        assert_eq!(
            cipolla(&379606557.into(), &425172197.into(), None),
            Some((143417827.into(), 281754370.into()))
        );
        assert_eq!(
            cipolla(&585251669.into(), &892950901.into(), None),
            Some((192354555.into(), 700596346.into()))
        );
        assert_eq!(
            cipolla(&404690348.into(), &430183399.into(), None),
            Some((57227138.into(), 372956261.into()))
        );
        assert_eq!(
            cipolla(&210205747.into(), &625380647.into(), None),
            Some((76810367.into(), 548570280.into()))
        );
    }

    #[test]
    fn cipolla_no_answer() {
        assert_eq!(cipolla(&650927.into(), &852167.into(), None), None);
    }

    #[test]
    fn attack() {
        let params = Parameters {
            e: 431136.into(),
            n: Some(Integer::from_str("20028075057119606470997653328367575574842932705433449252891751944512035408804821820769873249430620354064275333718899596327278738196065005682300472920563941347200970934154410074604218203986244135394019582138878032844785909718979603177656730281162130579832439207882805843512306359302587171301376824965170980858074723907").unwrap()),
            c: Some(Integer::from_str("2245426349205654220539251015376782389314381152940107065372050897628671922457608107732424988351371982603851427850123889275005370926571389796382801114705487071098812860917032260154888382308599420517334190150286342507371074105835709370331606232947681012019061355215611390935668580235727108722400967264420585384526616626").unwrap()),
            ..Default::default()
        };

        let solution = CipollaAttack.run(&params, None).unwrap();
        assert!(solution
            .ms
            .iter()
            .any(|m| *m == string_to_integer("RsaCracker")));
    }
}
