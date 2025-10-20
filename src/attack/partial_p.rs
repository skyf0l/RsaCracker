use indicatif::ProgressBar;
use rug::{Complete, Integer};

use crate::{Attack, AttackKind, AttackSpeed, Error, Parameters, PrivateKey, Solution};

/// Partial p leaked attack (MSB or LSB of p is known)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialPAttack;

impl Attack for PartialPAttack {
    fn name(&self) -> &'static str {
        "partial_p"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Medium
    }

    fn kind(&self) -> AttackKind {
        AttackKind::KnownExtraInformation
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;
        let p_partial = params.p.as_ref().ok_or(Error::MissingParameters)?;

        // Determine if we have LSB or MSB based on the trailing zeros
        // If p_partial has trailing zeros, assume it's MSB (lower bits cleared)
        // Otherwise, assume it's LSB
        
        let sqrt_n = n.sqrt_ref().complete();
        let p_bits = sqrt_n.significant_bits();
        let known_bits = p_partial.significant_bits();
        
        // Check if lower bits are zero (MSB case)
        let trailing_zeros = p_partial.find_one(0);
        
        if trailing_zeros.is_some() && trailing_zeros.unwrap() > 10 {
            // MSB known - brute force LSB
            let unknown_bits = trailing_zeros.unwrap();
            self.recover_from_msb(n, p_partial, unknown_bits, p_bits, pb, params)
        } else {
            // LSB known - brute force MSB
            self.recover_from_lsb(n, p_partial, known_bits, p_bits, pb, params)
        }
    }
}

impl PartialPAttack {
    fn recover_from_lsb(
        &self,
        n: &Integer,
        p_lsb: &Integer,
        known_bits: u32,
        total_bits: u32,
        pb: Option<&ProgressBar>,
        params: &Parameters,
    ) -> Result<Solution, Error> {
        let unknown_bits = total_bits - known_bits;
        if unknown_bits > 40 {
            // Too many bits to brute force
            return Err(Error::NotFound);
        }

        let max_iterations = 1u64 << unknown_bits;
        if let Some(pb) = pb {
            pb.set_length(max_iterations);
        }

        for i in 0..max_iterations {
            if let Some(pb) = pb {
                if i % 1000 == 0 {
                    pb.set_position(i);
                }
            }

            let msb_guess = Integer::from(i) << known_bits;
            let p_candidate = Integer::from(&msb_guess | p_lsb);

            if &p_candidate > &Integer::from(1) && Integer::from(n % &p_candidate) == 0 {
                let q = n.clone() / &p_candidate;
                
                return Ok(Solution {
                    m: None,
                    ms: Vec::new(),
                    pk: Some(PrivateKey::from_factors(
                        [p_candidate, q],
                        &params.e,
                    )?),
                    attack: self.name(),
                });
            }
        }

        Err(Error::NotFound)
    }

    fn recover_from_msb(
        &self,
        n: &Integer,
        p_msb: &Integer,
        unknown_bits: u32,
        _total_bits: u32,
        pb: Option<&ProgressBar>,
        params: &Parameters,
    ) -> Result<Solution, Error> {
        if unknown_bits > 40 {
            // Too many bits to brute force
            return Err(Error::NotFound);
        }

        let max_iterations = 1u64 << unknown_bits;
        if let Some(pb) = pb {
            pb.set_length(max_iterations);
        }

        let mask = (Integer::from(1) << unknown_bits) - 1u32;

        for i in 0..max_iterations {
            if let Some(pb) = pb {
                if i % 1000 == 0 {
                    pb.set_position(i);
                }
            }

            let lsb_guess = Integer::from(i) & &mask;
            let p_candidate = Integer::from(p_msb.clone() | lsb_guess);

            if &p_candidate > &Integer::from(1) && Integer::from(n % &p_candidate) == 0 {
                let q = n.clone() / &p_candidate;
                
                return Ok(Solution {
                    m: None,
                    ms: Vec::new(),
                    pk: Some(PrivateKey::from_factors(
                        [p_candidate, q],
                        &params.e,
                    )?),
                    attack: self.name(),
                });
            }
        }

        Err(Error::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rug::ops::Pow;

    use crate::{Attack, Parameters};

    use super::*;

    #[test]
    fn attack_lsb() {
        let p = Integer::from_str("9485522408934452514497044544810262480219745706849418879270371628992124322819346141601819527980635764688643085219938447441208608456294814911374531750726029").unwrap();
        let q = Integer::from_str("7236301337700681229488657348010407616853701897387177738886248001234670489179740400338396954495791474380867863525254462520148880017031349131800301481151767").unwrap();
        
        let n = p.clone() * &q;
        
        // Take lower bits as known, leaving only 20 unknown MSB bits
        let p_bits = p.significant_bits();
        let known_bits = p_bits - 20;
        let p_lsb = p.clone() % Integer::from(2).pow(known_bits);
        
        let params = Parameters {
            n: Some(n.clone()),
            p: Some(p_lsb),
            ..Default::default()
        };

        let solution = PartialPAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        // Factors might be swapped
        assert!(
            (pk.p() == p && pk.q() == q) || (pk.p() == q && pk.q() == p),
            "Factors don't match"
        );
    }

    #[test]
    fn attack_msb() {
        let p = Integer::from_str("9485522408934452514497044544810262480219745706849418879270371628992124322819346141601819527980635764688643085219938447441208608456294814911374531750726029").unwrap();
        let q = Integer::from_str("7236301337700681229488657348010407616853701897387177738886248001234670489179740400338396954495791474380867863525254462520148880017031349131800301481151767").unwrap();
        
        let n = p.clone() * &q;
        
        // Take upper bits as known (remove lower 16 bits)
        let unknown_bits = 16;
        let p_msb = (p.clone() >> unknown_bits) << unknown_bits;

        let params = Parameters {
            n: Some(n.clone()),
            p: Some(p_msb),
            ..Default::default()
        };

        let solution = PartialPAttack.run(&params, None).unwrap();
        let pk = solution.pk.unwrap();

        // Factors might be swapped
        assert!(
            (pk.p() == p && pk.q() == q) || (pk.p() == q && pk.q() == p),
            "Factors don't match"
        );
    }
}
