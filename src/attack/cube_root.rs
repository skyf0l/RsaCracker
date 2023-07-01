use rug::Integer;

use crate::{Attack, Error, Parameters, SolvedRsa};

/// Cube root attack (m^e < n and small e)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CubeRootAttack;

impl Attack for CubeRootAttack {
    fn name(&self) -> &'static str {
        "cube_root"
    }

    fn run(&self, params: &Parameters) -> Result<SolvedRsa, Error> {
        let e = &params.e;
        let c = params.c.as_ref().ok_or(Error::MissingParameters)?;

        if let Some(e) = e.to_u32() {
            let (root, rem) = c.root_rem_ref(e).into();
            if rem == Integer::ZERO {
                return Ok((None, Some(root)));
            }
        }
        Err(Error::NotFound)
    }
}
