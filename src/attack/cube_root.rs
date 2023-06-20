use rug::{ops::Pow, Integer};

use crate::{Attack, Error, Parameters, SolvedRsa};

/// Cube root attack (m < n/e and small e)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CubeRootAttack;

impl Attack for CubeRootAttack {
    fn name(&self) -> &'static str {
        "cube_root"
    }

    fn run(&self, params: &Parameters) -> Result<SolvedRsa, Error> {
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

        // Check if we found the exact cube root
        if low.clone().pow(e.to_u32().unwrap()) == *c {
            Ok((None, Some(low)))
        } else {
            Err(Error::NotFound)
        }
    }
}
