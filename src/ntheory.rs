use rug::{
    ops::{DivRounding, Pow},
    Integer,
};

pub fn rational_to_contfrac(x: &Integer, y: &Integer) -> Vec<Integer> {
    let a = x.clone().div_floor(y);

    if a.clone() * y == *x {
        vec![a]
    } else {
        let mut pquotients = rational_to_contfrac(y, &(x - a.clone() * y));
        pquotients.insert(0, a);
        pquotients
    }
}

pub fn contfrac_to_rational(frac: &[Integer]) -> (Integer, Integer) {
    if frac.is_empty() {
        (0.into(), 1.into())
    } else if frac.len() == 1 {
        (frac[0].clone(), 1.into())
    } else {
        let remainder = frac[1..frac.len()].to_vec();
        let (num, denom) = contfrac_to_rational(&remainder);
        (frac[0].clone() * num.clone() + denom, num)
    }
}

#[allow(dead_code)]
pub fn convergents_from_contfrac(frac: &[Integer]) -> Vec<(Integer, Integer)> {
    let mut convs = Vec::new();

    for i in 0..frac.len() {
        convs.push(contfrac_to_rational(&frac[0..i]));
    }
    convs
}

pub fn trivial_factorization_with_n_phi(n: &Integer, phi: &Integer) -> Option<(Integer, Integer)> {
    let m = n.clone() - phi.clone() + Integer::from(1);
    let m2n2 = m.clone().pow(2) - Integer::from(n << 2);

    if m2n2 > 0 {
        let (i, _) = m2n2.sqrt_rem(Integer::new());
        let roots: (Integer, Integer) = ((m.clone() - i.clone()) >> 1, (m + i) >> 1);

        if roots.0.clone() * roots.1.clone() == *n {
            return Some(roots);
        }
    }
    None
}

pub fn crt(residues: &[Integer], modulli: &[Integer]) -> Option<Integer> {
    let prod = modulli.iter().product::<Integer>();
    let mut sum = Integer::ZERO;

    for (residue, modulus) in residues.iter().zip(modulli) {
        let p = prod.clone() / modulus;
        sum += residue * Integer::from(p.invert_ref(modulus)?) * p
    }

    Some(sum % prod)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chinese_remainder_theorem() {
        assert_eq!(
            crt(
                &[3.into(), 5.into(), 7.into()],
                &[2.into(), 3.into(), 1.into()]
            ),
            Some(Integer::from(5))
        );
        assert_eq!(
            crt(
                &[1.into(), 4.into(), 6.into()],
                &[3.into(), 5.into(), 7.into()]
            ),
            Some(Integer::from(34))
        );
        assert_eq!(
            crt(
                &[1.into(), 4.into(), 6.into()],
                &[1.into(), 2.into(), 0.into()]
            ),
            None
        );
        assert_eq!(
            crt(
                &[2.into(), 5.into(), 7.into()],
                &[6.into(), 9.into(), 15.into()]
            ),
            None
        );
    }
}
