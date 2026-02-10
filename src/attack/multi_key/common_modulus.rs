use indicatif::ProgressBar;
use rug::Integer;

use crate::{Attack, AttackKind, AttackSpeed, Error, Parameters, Solution};

/// Common modulus attack
///
/// When the same message is encrypted with the same modulus n but different coprime exponents e1 and e2,
/// we can recover the plaintext without factoring n.
///
/// Given:
/// - c1 = m^e1 mod n
/// - c2 = m^e2 mod n
/// - gcd(e1, e2) = 1
///
/// We can find x, y such that: x*e1 + y*e2 = 1 (extended Euclidean algorithm)
/// Then: m = c1^x * c2^y mod n
///
/// See <https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Practical_attacks>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommonModulusAttack;

impl Attack for CommonModulusAttack {
    fn name(&self) -> &'static str {
        "common_modulus"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Fast
    }

    fn kind(&self) -> AttackKind {
        AttackKind::MultiKey
    }

    fn run(&self, params: &Parameters, _pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        // Need the main n, e, c and at least one additional key with same n
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;
        let e1 = &params.e;
        let c1 = params.c.as_ref().ok_or(Error::MissingParameters)?;

        // Find a key with the same modulus but different exponent
        for key in &params.keys {
            let key_n = key.n.as_ref().ok_or(Error::MissingParameters)?;
            let e2 = &key.e;
            let c2 = key.c.as_ref().ok_or(Error::MissingParameters)?;

            // Check if this key has the same modulus
            if key_n != n {
                continue;
            }

            // Check if exponents are different
            if e1 == e2 {
                continue;
            }

            // Check if exponents are coprime
            let gcd = Integer::from(e1.gcd_ref(e2));
            if gcd != 1 {
                continue;
            }

            // Use extended Euclidean algorithm to find x, y such that: x*e1 + y*e2 = 1
            let (_, x, y) = extended_gcd(e1, e2);

            // Compute m = c1^x * c2^y mod n
            let m = if x >= 0 && y >= 0 {
                // Both positive
                let m1 = c1.clone().pow_mod(&x.clone(), n).unwrap();
                let m2 = c2.clone().pow_mod(&y.clone(), n).unwrap();
                (m1 * m2) % n
            } else if x < 0 && y >= 0 {
                // x negative, need inverse of c1
                let c1_inv = match c1.clone().invert(n) {
                    Ok(inv) => inv,
                    Err(_) => return Err(Error::NotFound),
                };
                let m1 = c1_inv.pow_mod(&(-x).clone(), n).unwrap();
                let m2 = c2.clone().pow_mod(&y.clone(), n).unwrap();
                (m1 * m2) % n
            } else if x >= 0 && y < 0 {
                // y negative, need inverse of c2
                let c2_inv = match c2.clone().invert(n) {
                    Ok(inv) => inv,
                    Err(_) => return Err(Error::NotFound),
                };
                let m1 = c1.clone().pow_mod(&x.clone(), n).unwrap();
                let m2 = c2_inv.pow_mod(&(-y).clone(), n).unwrap();
                (m1 * m2) % n
            } else {
                // Both negative
                let c1_inv = match c1.clone().invert(n) {
                    Ok(inv) => inv,
                    Err(_) => return Err(Error::NotFound),
                };
                let c2_inv = match c2.clone().invert(n) {
                    Ok(inv) => inv,
                    Err(_) => return Err(Error::NotFound),
                };
                let m1 = c1_inv.pow_mod(&(-x).clone(), n).unwrap();
                let m2 = c2_inv.pow_mod(&(-y).clone(), n).unwrap();
                (m1 * m2) % n
            };

            return Ok(Solution::new_m(self.name(), m));
        }

        Err(Error::NotFound)
    }
}

/// Extended Euclidean algorithm
/// Returns (gcd, x, y) such that gcd = x*a + y*b
fn extended_gcd(a: &Integer, b: &Integer) -> (Integer, Integer, Integer) {
    if b == &0 {
        return (a.clone(), Integer::from(1), Integer::from(0));
    }

    let rem = Integer::from(a % b);
    let (gcd, x1, y1) = extended_gcd(b, &rem);
    let x = y1.clone();
    let div = Integer::from(a / b);
    let y = x1 - div * &y1;

    (gcd, x, y)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rug::Integer;

    use crate::{bytes_to_integer, Attack, KeyEntry, Parameters};

    use super::*;

    #[test]
    fn attack_basic() {
        let m = bytes_to_integer(b"RsaCracker!");
        let n = Integer::from_str("166270918338126577330758828592535648964989469159127542778196697837221437733066780089912708466193803018826184715618764250423068066614662326811797974314176667").unwrap();
        let e1 = Integer::from(65537);
        let e2 = Integer::from(65539);

        let c1 = m.clone().pow_mod(&e1, &n).unwrap();
        let c2 = m.clone().pow_mod(&e2, &n).unwrap();

        let params = Parameters {
            n: Some(n.clone()),
            e: e1,
            c: Some(c1),
            keys: vec![KeyEntry {
                n: Some(n),
                e: e2,
                c: Some(c2),
            }],
            ..Default::default()
        };

        let solution = CommonModulusAttack.run(&params, None).unwrap();
        assert_eq!(solution.m.unwrap(), m);
    }

    #[test]
    fn attack_larger_exponents() {
        let m = bytes_to_integer(b"Multi-key RSA attack!");
        let n = Integer::from_str("166270918338126577330758828592535648964989469159127542778196697837221437733066780089912708466193803018826184715618764250423068066614662326811797974314176667").unwrap();
        let e1 = Integer::from(17);
        let e2 = Integer::from(65537);

        let c1 = m.clone().pow_mod(&e1, &n).unwrap();
        let c2 = m.clone().pow_mod(&e2, &n).unwrap();

        let params = Parameters {
            n: Some(n.clone()),
            e: e1,
            c: Some(c1),
            keys: vec![KeyEntry {
                n: Some(n),
                e: e2,
                c: Some(c2),
            }],
            ..Default::default()
        };

        let solution = CommonModulusAttack.run(&params, None).unwrap();
        assert_eq!(solution.m.unwrap(), m);
    }

    #[test]
    fn attack_missing_parameters() {
        let params = Parameters {
            e: Integer::from(65537),
            ..Default::default()
        };

        let result = CommonModulusAttack.run(&params, None);
        assert!(matches!(result, Err(Error::MissingParameters)));
    }

    #[test]
    fn attack_same_exponent() {
        let m = bytes_to_integer(b"RsaCracker!");
        let n = Integer::from_str("166270918338126577330758828592535648964989469159127542778196697837221437733066780089912708466193803018826184715618764250423068066614662326811797974314176667").unwrap();
        let e = Integer::from(65537);

        let c1 = m.clone().pow_mod(&e, &n).unwrap();
        let c2 = m.clone().pow_mod(&e, &n).unwrap();

        let params = Parameters {
            n: Some(n.clone()),
            e: e.clone(),
            c: Some(c1),
            keys: vec![KeyEntry {
                n: Some(n),
                e,
                c: Some(c2),
            }],
            ..Default::default()
        };

        let result = CommonModulusAttack.run(&params, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_extended_gcd() {
        let a = Integer::from(65537);
        let b = Integer::from(65539);
        let (gcd, x, y) = extended_gcd(&a, &b);

        assert_eq!(gcd, Integer::from(1));
        assert_eq!(x * &a + y * &b, Integer::from(1));
    }
}
