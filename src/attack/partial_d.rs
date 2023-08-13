use indicatif::ProgressBar;
use rug::Integer;

use crate::{Attack, AttackSpeed, Error, KnownDAttack, Parameters, Solution};

/// Partial d leaked attack
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialDAttack;

impl Attack for PartialDAttack {
    fn name(&self) -> &'static str {
        "partial_d"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Fast
    }

    fn run(&self, params: &Parameters, _pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = &params.e;
        let e_u32 = match params.e.to_u32() {
            Some(e) => e,
            None => return Err(Error::NotFound),
        };
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;
        let d_lsb = params.d.as_ref().ok_or(Error::MissingParameters)?;

        let known_bits = d_lsb.significant_bits();

        for k in 1..e_u32 {
            let d_candidate = (n.clone() * k + 1u64) / e;
            let d_msb = (d_candidate >> known_bits) << known_bits;
            let d = d_msb | d_lsb;

            // Check congruence
            if Integer::from(e * &d) % k == 1 {
                // Try to encrypt and decrypt 2 to check if d is correct
                if Integer::from(2)
                    .pow_mod(e, n)
                    .unwrap()
                    .pow_mod(&d, n)
                    .unwrap()
                    == 2
                {
                    // Compute p and q
                    return KnownDAttack
                        .run(
                            &(Parameters {
                                d: Some(d),
                                ..Default::default()
                            } + params),
                            _pb,
                        )
                        .map(|mut s| {
                            s.attack = self.name();
                            s
                        });
                }
            }
        }

        Err(Error::NotFound)
    }
}
