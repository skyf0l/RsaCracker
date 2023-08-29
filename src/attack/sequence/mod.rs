mod factorial;
mod fermat;
mod fibonacci;
mod jacobsthal;
mod lucas;
mod mersenne;
mod primorial;
mod xy;

pub use factorial::*;
pub use fermat::*;
pub use fibonacci::*;
pub use jacobsthal::*;
pub use lucas::*;
pub use mersenne::*;
pub use primorial::*;
pub use xy::*;

#[cfg(test)]
mod tests {
    use rug::Integer;

    use crate::{Attack, Parameters};

    use super::*;

    macro_rules! gen_test {
        ($name:ident, $attack:ident) => {
            #[test]
            fn $name() {
                let p = Integer::from(97);
                let q = Integer::from(257);

                let params = Parameters {
                    n: Some(p.clone() * &q),
                    ..Default::default()
                };
                let solution = $name::$attack.run(&params, None).unwrap();
                let pk = solution.pk.unwrap();

                assert_eq!(pk.p(), p);
                assert_eq!(pk.q(), q);
            }
        };
    }

    gen_test!(factorial, FactorialGcdAttack);
    gen_test!(fermat, FermatGcdAttack);
    gen_test!(fibonacci, FibonacciGcdAttack);
    gen_test!(jacobsthal, JacobsthalGcdAttack);
    gen_test!(lucas, LucasGcdAttack);
    gen_test!(mersenne, MersenneGcdAttack);
    gen_test!(primorial, PrimorialGcdAttack);
    gen_test!(xy, XYGcdAttack);
}
