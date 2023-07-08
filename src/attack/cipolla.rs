use indicatif::ProgressBar;
use rug::Integer;
use std::rc::Rc;

use crate::{Attack, Error, Parameters, SolvedRsa};

// Inspired by https://github.com/TheAlgorithms/Rust/blob/master/src/math/quadratic_residue.rs

#[derive(Debug)]
struct CustomFiniteFiled {
    modulus: Integer,
    i_square: Integer,
}

impl CustomFiniteFiled {
    pub fn new(modulus: Integer, i_square: Integer) -> Self {
        Self { modulus, i_square }
    }
}

#[derive(Clone, Debug)]
struct CustomComplexNumber {
    real: Integer,
    imag: Integer,
    f: Rc<CustomFiniteFiled>,
}

impl CustomComplexNumber {
    pub fn new(real: Integer, imag: Integer, f: Rc<CustomFiniteFiled>) -> Self {
        Self { real, imag, f }
    }

    pub fn mult_other(&mut self, rhs: &Self) {
        let tmp = (self.imag.clone() * &rhs.real + &self.real * &rhs.imag) % &self.f.modulus;
        self.real = (self.real.clone() * &rhs.real
            + ((self.imag.clone() * &rhs.imag) % &self.f.modulus) * &self.f.i_square)
            % &self.f.modulus;
        self.imag = tmp;
    }

    pub fn mult_self(&mut self) {
        let tmp = (self.imag.clone() * &self.real + &self.real * &self.imag) % &self.f.modulus;
        self.real = (self.real.clone() * &self.real
            + ((self.imag.clone() * &self.imag) % &self.f.modulus) * &self.f.i_square)
            % &self.f.modulus;
        self.imag = tmp;
    }

    pub fn fast_power(mut base: Self, mut power: Integer) -> Self {
        let mut result = CustomComplexNumber::new(Integer::from(1), Integer::ZERO, base.f.clone());
        while power != Integer::ZERO {
            if power.is_odd() {
                result.mult_other(&base); // result *= base;
            }
            base.mult_self(); // base *= base;
            power >>= 1;
        }
        result
    }
}

fn is_residue(x: &Integer, modulus: &Integer) -> bool {
    let power = Integer::from(modulus - 1) >> 1;
    *x != 0 && Integer::from(x.pow_mod_ref(&power, modulus).unwrap()) == 1
}

// Returns two solutions (x1, x2) for Quadratic Residue problem x^2 = a (mod p), where p is an odd prime
// Returns None if no solution are found
pub fn cipolla(a: &Integer, p: &Integer, pb: Option<&ProgressBar>) -> Option<(Integer, Integer)> {
    let a = a.clone() % p;
    if a == 0 || a == 1 {
        return Some((a.clone(), (-a % p + p) % p));
    }
    if !is_residue(&a, p) {
        return None;
    }

    if let Some(pb) = pb {
        pb.set_length(1_000_000);
    }
    let mut r = 1;
    loop {
        if r == 0 || !is_residue(&((p.clone() + r * r - &a) % p), p) {
            break;
        }
        r += 1;
        if r % 10_000 == 0 {
            if let Some(pb) = pb {
                pb.inc(10_000);
            }
        }
        if r > 1_000_000 {
            // Limit to 1 million iterations
            return None;
        }
    }

    let filed = Rc::new(CustomFiniteFiled::new(
        p.clone(),
        (p.clone() + r * r - &a) % p,
    ));
    let comp = CustomComplexNumber::new(r.into(), Integer::from(1), filed);
    let power = (p.clone() + 1) >> 1;
    let x0 = CustomComplexNumber::fast_power(comp, power).real;
    let x1 = p.clone() - &x0;

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

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<SolvedRsa, Error> {
        let e = &params.e;
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;
        let c = params.c.as_ref().ok_or(Error::MissingParameters)?;

        let d = Integer::from(e / 2)
            .invert(&(Integer::from(n - 1) / 2))
            .or(Err(Error::NotFound))?;
        let m = c.clone().pow_mod(&d, n).unwrap();
        let (_m1, m2) = cipolla(&m, n, pb).ok_or(Error::NotFound)?;
        // TODO: return multiple solutions
        Ok((None, Some(m2)))
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_numbers() {
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
    fn random_numbers() {
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
    fn no_answer() {
        assert_eq!(cipolla(&650927.into(), &852167.into(), None), None);
    }
}
