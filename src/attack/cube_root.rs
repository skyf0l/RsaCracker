use indicatif::ProgressBar;
use rug::Integer;

use crate::{Attack, AttackKind, AttackSpeed, Error, Parameters, Solution};

/// Cube root attack (m^e < n and small e)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CubeRootAttack;

impl Attack for CubeRootAttack {
    fn name(&self) -> &'static str {
        "cube_root"
    }

    fn speed(&self) -> AttackSpeed {
        AttackSpeed::Fast
    }

    fn kind(&self) -> AttackKind {
        AttackKind::KnownExtraInformation
    }

    fn run(&self, params: &Parameters, _pb: Option<&ProgressBar>) -> Result<Solution, Error> {
        let e = match params.e.to_u32() {
            Some(e) => e,
            None => return Err(Error::NotFound),
        };
        let c = params.c.as_ref().ok_or(Error::MissingParameters)?;

        let (root, rem) = c.root_rem_ref(e).into();
        if rem == Integer::ZERO {
            return Ok(Solution::new_m(self.name(), root));
        }
        Err(Error::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use rug::ops::Pow;

    use crate::{bytes_to_integer, Attack, Parameters};

    use super::*;

    #[test]
    fn attack() {
        let m = bytes_to_integer(b"RsaCracker!");
        let e = Integer::from(19);
        let c = m.clone().pow(e.to_u32().unwrap());

        let params = Parameters {
            e,
            c: Some(c),
            ..Default::default()
        };

        let solution = CubeRootAttack.run(&params, None).unwrap();
        assert_eq!(solution.m.unwrap(), m);
    }
}
