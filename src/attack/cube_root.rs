use rug::{ops::Pow, Integer};

use crate::{Attack, AttackResult, Error, Parameters};

/// Cube root attack (m < n/e and small e)
pub struct CubeRootAttack;

impl Attack for CubeRootAttack {
    fn name() -> &'static str {
        "cube_root"
    }

    fn run(params: &Parameters) -> AttackResult {
        if params.e != 3 && params.e != 5 {
            return Err(Error::NotFound);
        }

        let e = params.e.clone();
        let c = params.c.as_ref().ok_or(Error::MissingParameters)?;
        let mut low = Integer::ZERO;
        let mut high = c.clone();

        while low < high {
            let mid: Integer = (low.clone() + high.clone()) >> 1;

            if mid.clone().pow(e.to_u32().unwrap()) < *c {
                low = mid + 1;
            } else {
                high = mid;
            }
        }

        Ok((None, Some(low)))
    }
}
