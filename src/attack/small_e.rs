use indicatif::ProgressBar;
use rug::Integer;

use crate::{Attack, Error, Parameters, Solution};

/// Small e attack (m^e = c + k * n, with k small)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmallEAttack;

impl Attack for SmallEAttack {
    fn name(&self) -> &'static str {
        "small_e"
    }

    fn run(&self, params: &Parameters, pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = match params.e.to_u32() {
            Some(e) => e,
            None => return Err(Error::NotFound),
        };
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;
        let c = params.c.as_ref().ok_or(Error::MissingParameters)?;

        if let Some(pb) = pb {
            pb.set_length(1000000);
        }
        for i in 1..1000000 {
            let enc = Integer::from(n) * Integer::from(i) + c.clone();
            let (root, rem) = enc.root_rem_ref(e).into();

            // If the root is perfect, we found the plaintext
            if rem == Integer::ZERO {
                return Ok(Solution::new_m(self.name(), root));
            }

            if i % 10000 == 0 {
                if let Some(pb) = pb {
                    pb.inc(10000);
                }
            }
        }
        Err(Error::NotFound)
    }
}
