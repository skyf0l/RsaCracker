use indicatif::ProgressBar;
use rug::{ops::Pow, Integer};

use crate::{key::PrivateKey, Attack, AttackKind, AttackSpeed, Error, Parameters, Solution};

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
        let mut moduli = Vec::new();
        let mut exponents = Vec::new();
        let mut ciphertexts = Vec::new();

        // Add the main modulus if present
        if let Some(n) = &params.n {
            moduli.push(n.clone());
            exponents.push(params.e.clone());
            ciphertexts.push(params.c.clone());
        }

        // Add all additional key moduli
        for key in &params.keys {
            if let Some(n) = &key.n {
                moduli.push(n.clone());
                exponents.push(key.e.clone());
                ciphertexts.push(key.c.clone());
            }
        }

        if moduli.len() < 2 {
            return Err(Error::MissingParameters);
        }

        // Try all pairs of moduli
        for i in 0..moduli.len() {
            for j in (i + 1)..moduli.len() {
                let p = Integer::from(moduli[i].gcd_ref(&moduli[j]));

                if p > 1 && p != moduli[i] && p != moduli[j] {
                    // Found a common factor!
                    // Use the modulus where we found the factor
                    let n = &moduli[i];
                    let e = &exponents[i];
                    let c = &ciphertexts[i];

                    let q = n.clone() / &p;
                    let phi = (p.clone() - 1) * (q.clone() - 1);

                    // Check if e and phi are coprime
                    let gcd_e_phi = e.clone().gcd(&phi);

                    if gcd_e_phi == 1 {
                        // Standard case: e and phi are coprime
                        return Ok(Solution::new_pk(
                            self.name(),
                            PrivateKey::from_p_q(p, q, e)?,
                        ));
                    } else if c.is_some() {
                        // Non-coprime exponent case: need to handle specially
                        // Factor e = e1 * e2 where e1 = gcd(e, phi)
                        let e1 = gcd_e_phi;
                        let e2 = e.clone() / &e1;

                        // Check if e2 and phi/e1 are coprime
                        let phi_reduced = phi.clone() / &e1;
                        if e2.clone().gcd(&phi_reduced) != 1 {
                            // Can't handle this case, try next pair
                            continue;
                        }

                        // Compute d using e2 instead of e
                        let d = match e2.clone().invert(&phi_reduced) {
                            Ok(d) => d,
                            Err(_) => continue, // Try next pair
                        };

                        // Decrypt: m^e1 = c^d mod n
                        let c = c.as_ref().unwrap();
                        let m_to_e1 = match c.clone().pow_mod(&d, n) {
                            Ok(val) => val,
                            Err(_) => continue, // Try next pair
                        };

                        // Take the e1-th root of m_to_e1 to get m
                        // For e1 = 2, we can use integer square root
                        // (works when m^2 < n, which is usually the case for messages)
                        if e1 == 2 {
                            let m = m_to_e1.clone().sqrt();
                            // Verify it's correct
                            if m.clone() * &m == m_to_e1 {
                                return Ok(Solution::new_m(self.name(), m));
                            }
                        } else if e1 == 3 {
                            // For cube root
                            let m = m_to_e1.clone().root(3);
                            // Verify it's correct
                            if m.clone().pow(3) == m_to_e1 {
                                return Ok(Solution::new_m(self.name(), m));
                            }
                        } else {
                            // For other roots, try integer root
                            if let Some(e1_u32) = e1.to_u32() {
                                let m = m_to_e1.clone().root(e1_u32);
                                // Verify it's correct
                                if m.clone().pow(e1_u32) == m_to_e1 {
                                    return Ok(Solution::new_m(self.name(), m));
                                }
                            }
                        }
                    }

                    // If we get here, we found the factors but couldn't decrypt
                    // Try to return the private key anyway (might fail)
                    if let Ok(pk) = PrivateKey::from_p_q(p, q, e) {
                        return Ok(Solution::new_pk(self.name(), pk));
                    }
                }
            }
        }

        Err(Error::NotFound)
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

    #[test]
    fn attack_missing_moduli() {
        let e = Integer::from(65537);

        let params = Parameters {
            e,
            ..Default::default()
        };

        let result = CommonFactorAttack.run(&params, None);
        assert!(matches!(result, Err(Error::MissingParameters)));
    }

    #[test]
    fn attack_noncoprime_exponent_square_root() {
        // Test with non-coprime exponent where gcd(e, phi) = 2
        // Based on BSides Delhi 2018 challenge
        let n1 = Integer::from_str("143786356117385195355522728814418684024129402954309769186869633376407480449846714776247533950484109173163811708549269029920405450237443197994941951104068001708682945191370596050916441792714228818475059839352105948003874426539429621408867171203559281132589926504992702401428910240117807627890055235377744541913").unwrap();
        let e1 = Integer::from(114194); // e1 is even: 114194 = 2 * 57097
        let c1 = Integer::from_str_radix("31c2fbff33dec7b070cf737c57393c8ab9982ae51b87b64d001a00aa74264254159e81e13b82ac5bc4d7f38aead06fabbf5b21ee668700a44673fac75bc09b084e79513ada3d11b248ae5fca74ba0c2f807e73052f3090ee61a3bd226e14f4b0544f952449623b8cbd01cc42ff5462c4904d0c28af6dbce73596de45279461fd", 16).unwrap();

        let n4 = Integer::from_str("119235191922699211973494433973985286182951917872084464216722572875998345005104112625024274855529546680909781406076412741844254205002739352725207590519921992295941563460138887173402493503653397592300336588721082590464192875253265214253650991510709511154297580284525736720396804660126786258245028204861220690641").unwrap();
        let e4 = Integer::from(79874); // e4 is even: 79874 = 2 * 39937

        let params = Parameters {
            n: Some(n1),
            e: e1,
            c: Some(c1),
            keys: vec![KeyEntry {
                n: Some(n4),
                e: e4,
                c: None,
            }],
            ..Default::default()
        };

        let solution = CommonFactorAttack.run(&params, None).unwrap();

        // Should successfully decrypt using non-coprime exponent handling
        assert_eq!(solution.attack, "common_factor");
        assert!(solution.m.is_some());

        // Verify the decrypted message is valid
        let m = solution.m.unwrap();
        assert!(m > 0);

        // Convert to bytes and check it's a valid message
        use crate::integer_to_string;
        let plaintext = integer_to_string(&m).unwrap();
        assert!(plaintext.contains("crypton{"));
    }

    #[test]
    fn attack_coprime_still_works() {
        // Verify that coprime exponents still work as before
        let p1 = Integer::from_str("12704460451534494031967012610385124349946784529699670611312906119052340494225557086421265132203129766891315537215217611630798386899633253559211223631146991").unwrap();
        let q1 = Integer::from_str("13082768051807546995723405137915083607226493252598950098559500283057676054655289649034281301331433871693649745132486183849864220126643322709682774011809557").unwrap();
        let p2 = p1.clone();
        let q2 = Integer::from_str("10846735654326787878163407853463542565347654325489765432546578765432198765432198765432198765432198765432198765432198765432198765432198765432187654321").unwrap();

        let n1 = p1.clone() * &q1;
        let n2 = p2.clone() * &q2;
        let e = Integer::from(65537); // Standard coprime exponent

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
}
