use indicatif::ProgressBar;
use rug::{ops::Pow, Integer};

use crate::{key::PrivateKey, Attack, AttackKind, AttackSpeed, Error, Parameters, Solution};

/// Data for a single RSA key in the common factor attack
struct KeyData {
    n: Integer,
    e: Integer,
    c: Option<Integer>,
}

/// Common factor attack for multiple RSA keys
///
/// When multiple RSA moduli share a common prime factor, their GCD reveals that factor.
/// This attack computes GCD of all pairs of moduli to find common factors.
///
/// See <https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Practical_attacks>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommonFactorAttack;

impl Attack for CommonFactorAttack {
    fn name(&self) -> &'static str {
        "common_factor"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Fast
    }

    fn kind(&self) -> AttackKind {
        AttackKind::KnownExtraInformation
    }

    fn run(&self, params: &Parameters, _pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        // Need at least 2 keys (including the main one if n is present)
        let mut keys = Vec::new();

        // Add the main modulus if present
        if let Some(n) = &params.n {
            keys.push(KeyData {
                n: n.clone(),
                e: params.e.clone(),
                c: params.c.clone(),
            });
        }

        // Add all additional key moduli
        for key in &params.keys {
            if let Some(n) = &key.n {
                keys.push(KeyData {
                    n: n.clone(),
                    e: key.e.clone(),
                    c: key.c.clone(),
                });
            }
        }

        if keys.len() < 2 {
            return Err(Error::MissingParameters);
        }

        // Try all pairs of moduli
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                let p = Integer::from(keys[i].n.gcd_ref(&keys[j].n));

                if p > 1 && p != keys[i].n && p != keys[j].n {
                    // Found a common factor!
                    let key = &keys[i];
                    let q = key.n.clone() / &p;
                    let phi = (p.clone() - 1) * (q.clone() - 1);

                    // Check if e and phi are coprime
                    let gcd_e_phi = key.e.clone().gcd(&phi);

                    if gcd_e_phi == 1 {
                        // Standard case: e and phi are coprime
                        return Ok(Solution::new_pk(
                            self.name(),
                            PrivateKey::from_p_q(p, q, &key.e)?,
                        ));
                    } else if let Some(c) = &key.c {
                        // Non-coprime exponent case: try to decrypt
                        if let Some(m) = try_decrypt_noncoprime(&key.e, &phi, c, &key.n) {
                            return Ok(Solution::new_m(self.name(), m));
                        }
                    }

                    // If we get here, we found the factors but couldn't decrypt
                    // Try to return the private key anyway (might fail)
                    if let Ok(pk) = PrivateKey::from_p_q(p, q, &key.e) {
                        return Ok(Solution::new_pk(self.name(), pk));
                    }
                }
            }
        }

        Err(Error::NotFound)
    }
}

/// Try to decrypt a message when the exponent is non-coprime with phi
///
/// When gcd(e, phi) > 1, we factor e = e1 * e2 where e1 = gcd(e, phi),
/// compute d = e2^-1 mod (phi/e1), decrypt to get m^e1, then take the e1-th root.
fn try_decrypt_noncoprime(e: &Integer, phi: &Integer, c: &Integer, n: &Integer) -> Option<Integer> {
    // Factor e = e1 * e2 where e1 = gcd(e, phi)
    let e1 = e.gcd(phi);
    let e2 = e / &e1;

    // Check if e2 and phi/e1 are coprime
    let phi_reduced = phi.clone() / &e1;
    if e2.gcd(&phi_reduced) != 1 {
        return None;
    }

    // Compute d using e2 instead of e
    let d = e2.invert(&phi_reduced).ok()?;

    // Decrypt: m^e1 = c^d mod n
    let m_to_e1 = c.clone().pow_mod(&d, n).ok()?;

    // Take the e1-th root to get m
    let e1_u32 = e1.to_u32()?;
    let m = m_to_e1.clone().root(e1_u32);

    // Verify it's correct (need to check before consuming m)
    let m_powered = m.clone().pow(e1_u32);
    if m_powered == m_to_e1 {
        Some(m)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rug::Integer;

    use crate::{factors::Factors, Attack, KeyEntry, Parameters};

    use super::*;

    #[test]
    fn attack_two_keys() {
        let p1 = Integer::from_str("12704460451534494031967012610385124349946784529699670611312906119052340494225557086421265132203129766891315537215217611630798386899633253559211223631146991").unwrap();
        let q1 = Integer::from_str("13082768051807546995723405137915083607226493252598950098559500283057676054655289649034281301331433871693649745132486183849864220126643322709682774011809557").unwrap();
        let p2 = p1.clone(); // Common factor
        let q2 = Integer::from_str("10846735654326787878163407853463542565347654325489765432546578765432198765432198765432198765432198765432198765432198765432198765432198765432187654321").unwrap();

        let n1 = p1.clone() * &q1;
        let n2 = p2.clone() * &q2;
        let e = Integer::from(65537);

        let params = Parameters {
            n: Some(n1.clone()),
            e: e.clone(),
            keys: vec![KeyEntry {
                n: Some(n2),
                e: e.clone(),
                c: None,
            }],
            ..Default::default()
        };

        let solution = CommonFactorAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.factors, Factors::from([p1, q1]));
    }

    #[test]
    fn attack_three_keys() {
        let p = Integer::from_str("12704460451534494031967012610385124349946784529699670611312906119052340494225557086421265132203129766891315537215217611630798386899633253559211223631146991").unwrap();
        let q1 = Integer::from_str("13082768051807546995723405137915083607226493252598950098559500283057676054655289649034281301331433871693649745132486183849864220126643322709682774011809557").unwrap();
        let q2 = Integer::from_str("10846735654326787878163407853463542565347654325489765432546578765432198765432198765432198765432198765432198765432198765432198765432198765432187654321").unwrap();
        let q3 = Integer::from_str("98765432109876543210987654321098765432109876543210987654321098765432109876543210987654321098765432109876543210987654321098765432109876543210987654321").unwrap();

        let n1 = p.clone() * &q1;
        let n2 = p.clone() * &q2;
        let n3 = p.clone() * &q3;
        let e = Integer::from(65537);

        let params = Parameters {
            n: Some(n1.clone()),
            e: e.clone(),
            keys: vec![
                KeyEntry {
                    n: Some(n2),
                    e: e.clone(),
                    c: None,
                },
                KeyEntry {
                    n: Some(n3),
                    e: e.clone(),
                    c: None,
                },
            ],
            ..Default::default()
        };

        let solution = CommonFactorAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        assert_eq!(pk.factors, Factors::from([p, q1]));
    }

    #[test]
    fn attack_no_common_factor() {
        let p1 = Integer::from_str("12704460451534494031967012610385124349946784529699670611312906119052340494225557086421265132203129766891315537215217611630798386899633253559211223631146991").unwrap();
        let q1 = Integer::from_str("13082768051807546995723405137915083607226493252598950098559500283057676054655289649034281301331433871693649745132486183849864220126643322709682774011809557").unwrap();
        let p2 = Integer::from_str("10846735654326787878163407853463542565347654325489765432546578765432198765432198765432198765432198765432198765432198765432198765432198765432187654321").unwrap();
        let q2 = Integer::from_str("98765432109876543210987654321098765432109876543210987654321098765432109876543210987654321098765432109876543210987654321098765432109876543210987654321").unwrap();

        let n1 = p1 * &q1;
        let n2 = p2 * &q2;
        let e = Integer::from(65537);

        let params = Parameters {
            n: Some(n1),
            e: e.clone(),
            keys: vec![KeyEntry {
                n: Some(n2),
                e,
                c: None,
            }],
            ..Default::default()
        };

        let result = CommonFactorAttack.run(&params, None);
        assert!(result.is_err());
    }
}
