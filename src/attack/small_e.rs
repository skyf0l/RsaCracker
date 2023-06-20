use std::ops::Mul;

use rug::{ops::Pow, Integer};

use crate::{Attack, Error, Parameters, SolvedRsa};

/// Small e attack (m^e = c + k * n, with k small)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmallEAttack;

impl Attack for SmallEAttack {
    fn name(&self) -> &'static str {
        "small_e"
    }

    fn run(&self, params: &Parameters) -> Result<SolvedRsa, Error> {
        if params.e != 3 && params.e != 5 {
            return Err(Error::NotFound);
        }
        let e = params.e.to_u32().unwrap();
        let n = params.n.as_ref().ok_or(Error::MissingParameters)?;
        let c = params.c.as_ref().ok_or(Error::MissingParameters)?;

        for i in 1..10000 {
            let enc = Mul::<Integer>::mul(n, i.into()) + c.clone();
            let root = enc.clone().root(e);

            // If the root is perfect, we found the plaintext
            if root.clone().pow(e) == enc {
                return Ok((None, Some(root)));
            }
        }
        Err(Error::NotFound)
    }
}
