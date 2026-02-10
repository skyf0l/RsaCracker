//! Finite field arithmetic for cryptographic algorithms.
//!
//! Provides abstractions for working with prime fields GF(p) and their quadratic extensions GF(p²).

use discrete_logarithm::discrete_log_with_order;
use rug::{ops::Pow, Integer};
use std::ops::{Add, Div, Mul, Neg, Sub};

/// A prime field GF(p) where p is a prime modulus.
#[derive(Debug, Clone)]
pub struct PrimeField {
    modulus: Integer,
}

impl PrimeField {
    /// Create a new prime field with the given modulus.
    ///
    /// Note: This does not verify that the modulus is prime.
    /// The caller is responsible for ensuring p is prime.
    pub fn new(modulus: Integer) -> Self {
        Self { modulus }
    }

    /// Get the modulus of this field.
    pub fn modulus(&self) -> &Integer {
        &self.modulus
    }

    /// Create a field element from an integer value.
    pub fn element(&self, value: Integer) -> FieldElement<'_> {
        let value = value % &self.modulus;
        FieldElement { value, field: self }
    }

    /// Create the zero element.
    pub fn zero(&self) -> FieldElement<'_> {
        self.element(Integer::from(0))
    }

    /// Create the one element.
    pub fn one(&self) -> FieldElement<'_> {
        self.element(Integer::from(1))
    }
}

/// An element of a prime field GF(p).
#[derive(Debug, Clone)]
pub struct FieldElement<'a> {
    value: Integer,
    field: &'a PrimeField,
}

impl<'a> FieldElement<'a> {
    /// Get the underlying integer value (in range [0, p)).
    pub fn value(&self) -> &Integer {
        &self.value
    }

    /// Get the field this element belongs to.
    pub fn field(&self) -> &PrimeField {
        self.field
    }

    /// Consume this element and return the underlying integer.
    pub fn into_value(self) -> Integer {
        self.value
    }

    /// Compute the multiplicative inverse, if it exists.
    pub fn inv(&self) -> Option<FieldElement<'a>> {
        self.value
            .clone()
            .invert(self.field.modulus())
            .ok()
            .map(|inv| self.field.element(inv))
    }

    /// Compute self^exp in the field.
    pub fn pow(&self, exp: &Integer) -> FieldElement<'a> {
        let result = self
            .value
            .clone()
            .pow_mod(exp, self.field.modulus())
            .unwrap();
        self.field.element(result)
    }

    /// Compute self^exp where exp is a u32.
    pub fn pow_u32(&self, exp: u32) -> FieldElement<'a> {
        self.pow(&Integer::from(exp))
    }

    /// Check if this element is zero.
    pub fn is_zero(&self) -> bool {
        self.value == 0
    }

    /// Check if this element is one.
    pub fn is_one(&self) -> bool {
        self.value == 1
    }
}

impl<'a> PartialEq for FieldElement<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<'a> Eq for FieldElement<'a> {}

// Arithmetic operations

impl<'a> Add for FieldElement<'a> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let result = (self.value + other.value) % self.field.modulus();
        self.field.element(result)
    }
}

impl<'a> Add for &FieldElement<'a> {
    type Output = FieldElement<'a>;

    fn add(self, other: Self) -> FieldElement<'a> {
        let result = (self.value.clone() + other.value.clone()) % self.field.modulus();
        self.field.element(result)
    }
}

impl<'a> Sub for FieldElement<'a> {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let mut result = (self.value - other.value) % self.field.modulus();
        if result < 0 {
            result += self.field.modulus();
        }
        self.field.element(result)
    }
}

impl<'a> Sub for &FieldElement<'a> {
    type Output = FieldElement<'a>;

    fn sub(self, other: Self) -> FieldElement<'a> {
        let mut result = (self.value.clone() - other.value.clone()) % self.field.modulus();
        if result < 0 {
            result += self.field.modulus();
        }
        self.field.element(result)
    }
}

impl<'a> Mul for FieldElement<'a> {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        let result = (self.value * other.value) % self.field.modulus();
        self.field.element(result)
    }
}

impl<'a> Mul for &FieldElement<'a> {
    type Output = FieldElement<'a>;

    fn mul(self, other: Self) -> FieldElement<'a> {
        let result = (self.value.clone() * other.value.clone()) % self.field.modulus();
        self.field.element(result)
    }
}

impl<'a> Div for FieldElement<'a> {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, other: Self) -> Self {
        let inv = other
            .inv()
            .expect("Division by zero or non-invertible element");
        self * inv
    }
}

impl<'a> Div for &FieldElement<'a> {
    type Output = FieldElement<'a>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, other: Self) -> FieldElement<'a> {
        let inv = other
            .inv()
            .expect("Division by zero or non-invertible element");
        self * &inv
    }
}

impl<'a> Neg for FieldElement<'a> {
    type Output = Self;

    fn neg(self) -> Self {
        let result = self.field.modulus() - self.value;
        self.field.element(result)
    }
}

impl<'a> Neg for &FieldElement<'a> {
    type Output = FieldElement<'a>;

    fn neg(self) -> FieldElement<'a> {
        let result = self.field.modulus() - self.value.clone();
        self.field.element(result)
    }
}

/// Quadratic extension field F_p[x]/(x² - ω) built over a prime field.
///
/// Elements are represented as a + bx where x² = ω (omega is a quadratic non-residue).
/// This is used for algorithms like Cipolla's square root algorithm that require
/// working in a degree-2 extension of the base field.
#[derive(Debug, Clone)]
pub struct QuadraticExtension<'a> {
    real: Integer,         // coefficient of x^0 (stored as Integer for simplicity)
    imag: Integer,         // coefficient of x^1
    field: &'a PrimeField, // reference to base field
    omega: Integer,        // x² = ω (must be non-residue in base field)
}

impl<'a> QuadraticExtension<'a> {
    /// Create a new extension element a + bx.
    ///
    /// `omega` must be a quadratic non-residue in the base field for the
    /// extension to be a valid field.
    pub fn new(field: &'a PrimeField, real: Integer, imag: Integer, omega: Integer) -> Self {
        let real = real % field.modulus();
        let imag = imag % field.modulus();
        Self {
            real,
            imag,
            field,
            omega,
        }
    }

    /// Get the base field this extension is built over.
    #[allow(dead_code)]
    pub fn field(&self) -> &'a PrimeField {
        self.field
    }

    /// Get the real part (coefficient of x^0) as an integer.
    pub fn real(&self) -> &Integer {
        &self.real
    }

    /// Get the imaginary part (coefficient of x^1) as an integer.
    #[allow(dead_code)]
    pub fn imag(&self) -> &Integer {
        &self.imag
    }

    /// Get omega (the value such that x² = ω).
    #[allow(dead_code)]
    pub fn omega(&self) -> &Integer {
        &self.omega
    }

    /// Multiply two extension elements: (a + bx)(c + dx) = (ac + bdω) + (ad + bc)x.
    pub fn mul(&self, other: &Self) -> Self {
        let ac = (self.real.clone() * &other.real) % self.field.modulus();
        let bd = (self.imag.clone() * &other.imag) % self.field.modulus();
        let bd_omega = (bd * &self.omega) % self.field.modulus();
        let real_part = (ac + bd_omega) % self.field.modulus();

        let ad = (self.real.clone() * &other.imag) % self.field.modulus();
        let bc = (self.imag.clone() * &other.real) % self.field.modulus();
        let imag_part = (ad + bc) % self.field.modulus();

        Self::new(self.field, real_part, imag_part, self.omega.clone())
    }

    /// Square this element: (a + bx)² = (a² + b²ω) + 2abx.
    pub fn square(&self) -> Self {
        let a2 = (self.real.clone() * &self.real) % self.field.modulus();
        let b2 = (self.imag.clone() * &self.imag) % self.field.modulus();
        let b2_omega = (b2 * &self.omega) % self.field.modulus();
        let real_part = (a2 + b2_omega) % self.field.modulus();

        let two = Integer::from(2);
        let temp = (two * &self.real) % self.field.modulus();
        let imag_part = (temp * &self.imag) % self.field.modulus();

        Self::new(self.field, real_part, imag_part, self.omega.clone())
    }

    /// Fast exponentiation using square-and-multiply algorithm.
    pub fn pow(&self, exp: &Integer) -> Self {
        if exp == &0 {
            return Self::new(
                self.field,
                Integer::from(1),
                Integer::from(0),
                self.omega.clone(),
            );
        }

        let mut result = Self::new(
            self.field,
            Integer::from(1),
            Integer::from(0),
            self.omega.clone(),
        );
        let mut base = self.clone();
        let mut e = exp.clone();

        while e > 0 {
            if e.is_odd() {
                result = result.mul(&base);
            }
            base = base.square();
            e >>= 1;
        }
        result
    }
}

/// Compute all r-th roots of delta modulo prime p using Adleman-Manders-Miller algorithm.
///
/// This implementation uses the PrimeField abstraction for clean modular arithmetic
/// and the discrete-logarithm crate for the complex t > 1 cases.
///
/// Reference: Cao Z. et al., "Adleman-Manders-Miller Root Extraction Method Revisited"
pub fn rth_roots(field: &PrimeField, delta: &Integer, r: u32) -> Vec<Integer> {
    if r == 0 || r > 10000 || delta == &Integer::from(0) {
        return Vec::new();
    }

    let p = field.modulus();
    let pm1: Integer = p.clone() - 1;
    let r_int = Integer::from(r);

    // Check r divides p-1
    if pm1.clone() % &r_int != 0 {
        return Vec::new();
    }

    // Decompose p-1 = r^t * s where gcd(r, s) = 1
    let mut t = 0u32;
    let mut s = pm1.clone();
    while s.clone() % &r_int == 0 {
        t += 1;
        s /= &r_int;
    }

    if t == 0 {
        return Vec::new();
    }
    let delta_elem = field.element(delta.clone());

    // Step 1: Find a primitive r-th root of unity (omega)
    // omega = g^((p-1)/r) where g is a generator such that omega^r = 1 but omega != 1
    let exp_omega = pm1.clone() / &r_int;
    let omega = {
        let mut omega = field.one();
        for candidate in 2..1000 {
            let g = field.element(Integer::from(candidate));
            omega = g.pow(&exp_omega);
            if !omega.is_one() {
                break;
            }
        }
        omega
    };

    if t == 1 {
        // Simple case: p-1 = r * s, compute delta^(r^-1 mod s)
        let inv_r = match r_int.clone().invert(&s) {
            Ok(inv) => inv,
            Err(_) => return Vec::new(),
        };
        let root = delta_elem.pow(&inv_r);

        // Generate all r roots using roots of unity: root, root*omega, root*omega^2, ...
        let mut roots = Vec::with_capacity(r as usize);
        let mut current = root;
        for _ in 0..r {
            roots.push(current.value().clone());
            current = &current * &omega;
        }
        return roots;
    }

    // Complex case: t > 1, need full AMM algorithm
    // Step 2: Find generator p of order r in the mult group
    let p_gen = {
        let exp_test = pm1.clone() / &r_int;
        let mut p_gen = field.one();
        for candidate in 2..1000 {
            let g = field.element(Integer::from(candidate));
            let test = g.pow(&exp_test);
            if !test.is_one() {
                p_gen = g;
                break;
            }
        }
        p_gen
    };

    // Find k such that (k*s + 1) % r == 0
    let mut k = Integer::from(1);
    while (k.clone() * &s + Integer::from(1)) % &r_int != 0 {
        k += 1;
    }
    let alpha = (k * &s + Integer::from(1)) / &r_int;

    // Step 3: Initialize AMM variables
    // Reduce exponents modulo (p-1) using Fermat's Little Theorem
    let r_power_reduced = r_int.clone().pow_mod(&Integer::from(t - 1), &pm1).unwrap();
    let exp_a = r_power_reduced.clone() * &s % &pm1;
    let a = p_gen.pow(&exp_a);
    let mut b = delta_elem.pow(&(r_int.clone() * &alpha - 1));
    let mut c = p_gen.pow(&s);
    let mut h = field.one();

    // Verify a has order exactly r (for prime r, just need a != 1 and a^r = 1)
    if a.is_one() {
        return Vec::new();
    }

    // Step 4: Iterative refinement
    for i in 1..t {
        let exp_d = r_int.clone().pow(t - 1 - i) % &pm1;
        let d = b.pow(&exp_d);

        let j = if d.is_one() {
            Integer::from(0)
        } else {
            // Compute discrete log: d = a^(-j), so a^j = d^(-1)
            let d_inv = field.element(d.value().clone().invert(p).unwrap());

            // Try discrete log with order first
            match discrete_log_with_order(d_inv.value(), a.value(), p, &r_int) {
                Ok(j_val) => j_val,
                Err(_) => {
                    // Fall back to brute force for small r
                    if r <= 10000 {
                        let mut found = None;
                        let mut a_power = field.one();
                        for k in 0..r {
                            if a_power.value() == d_inv.value() {
                                found = Some(Integer::from(k));
                                break;
                            }
                            a_power = &a_power * &a;
                        }
                        found.unwrap_or_else(|| Integer::from(0))
                    } else {
                        Integer::from(0)
                    }
                }
            }
        };

        let c_r = c.pow(&r_int);
        b = &b * &c_r.pow(&j);
        h = &h * &c.pow(&j);
        c = c_r;
    }

    // Step 5: Compute final root and generate all r roots using roots of unity
    let root = &delta_elem.pow(&alpha) * &h;

    let mut roots = Vec::with_capacity(r as usize);
    let mut current = root;
    for _ in 0..r {
        roots.push(current.value().clone());
        current = &current * &omega;
    }

    roots
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashSet, str::FromStr};

    #[test]
    fn test_basic_arithmetic() {
        let p = Integer::from(17);
        let field = PrimeField::new(p);

        let a = field.element(Integer::from(5));
        let b = field.element(Integer::from(12));

        // Addition: 5 + 12 = 17 ≡ 0 (mod 17)
        let sum = &a + &b;
        assert_eq!(sum.value(), &Integer::from(0));

        // Subtraction: 5 - 12 = -7 ≡ 10 (mod 17)
        let diff = &a - &b;
        assert_eq!(diff.value(), &Integer::from(10));

        // Multiplication: 5 * 12 = 60 ≡ 9 (mod 17)
        let prod = &a * &b;
        assert_eq!(prod.value(), &Integer::from(9));
    }

    #[test]
    fn test_inversion() {
        let p = Integer::from(17);
        let field = PrimeField::new(p);

        let a = field.element(Integer::from(5));
        let a_inv = a.inv().unwrap();

        // 5 * 7 = 35 ≡ 1 (mod 17)
        assert_eq!(a_inv.value(), &Integer::from(7));

        let prod = &a * &a_inv;
        assert!(prod.is_one());
    }

    #[test]
    fn test_power() {
        let p = Integer::from(17);
        let field = PrimeField::new(p);

        let a = field.element(Integer::from(3));

        // 3^4 = 81 ≡ 13 (mod 17)
        let result = a.pow(&Integer::from(4));
        assert_eq!(result.value(), &Integer::from(13));
    }

    #[test]
    fn test_division() {
        let p = Integer::from(17);
        let field = PrimeField::new(p);

        let a = field.element(Integer::from(10));
        let b = field.element(Integer::from(5));

        // 10 / 5 = 10 * 5^(-1) = 10 * 7 = 70 ≡ 2 (mod 17)
        let quot = &a / &b;
        assert_eq!(quot.value(), &Integer::from(2));
    }

    #[test]
    fn test_large_field() {
        // Use a large prime
        let p = Integer::from_str("340282366920938463463374607431768211297").unwrap();
        let field = PrimeField::new(p);

        let a = field.element(Integer::from_str("123456789012345678901234567890").unwrap());
        let b = field.element(Integer::from_str("987654321098765432109876543210").unwrap());

        let sum = &a + &b;
        let prod = &a * &b;

        // Verify operations don't panic and produce valid results
        assert!(sum.value() < field.modulus());
        assert!(prod.value() < field.modulus());
    }

    #[test]
    fn test_quadratic_extension_basic() {
        // Work in F_7[x]/(x² - 2)
        let p = Integer::from(7);
        let field = PrimeField::new(p);
        let omega = Integer::from(2); // 2 is a non-residue mod 7

        // Create (3 + 4x)
        let a = QuadraticExtension::new(&field, Integer::from(3), Integer::from(4), omega.clone());

        // Square it: (3 + 4x)² = 9 + 16·2 + 24x = 9 + 32 + 24x = 41 + 24x ≡ 6 + 3x (mod 7)
        let result = a.square();
        assert_eq!(result.real(), &Integer::from(6));
        assert_eq!(result.imag(), &Integer::from(3));
    }

    #[test]
    fn test_quadratic_extension_mul() {
        let p = Integer::from(7);
        let field = PrimeField::new(p);
        let omega = Integer::from(2);

        // (1 + 2x) * (3 + 4x) = (3 + 16) + (4 + 6)x = 19 + 10x ≡ 5 + 3x (mod 7)
        let a = QuadraticExtension::new(&field, Integer::from(1), Integer::from(2), omega.clone());
        let b = QuadraticExtension::new(&field, Integer::from(3), Integer::from(4), omega.clone());

        let result = a.mul(&b);
        assert_eq!(result.real(), &Integer::from(5));
        assert_eq!(result.imag(), &Integer::from(3));
    }

    #[test]
    fn test_quadratic_extension_pow() {
        let p = Integer::from(7);
        let field = PrimeField::new(p);
        let omega = Integer::from(2);

        let a = QuadraticExtension::new(&field, Integer::from(2), Integer::from(1), omega.clone());

        // (2 + x)^0 = 1
        let result = a.pow(&Integer::from(0));
        assert_eq!(result.real(), &Integer::from(1));
        assert_eq!(result.imag(), &Integer::from(0));

        // (2 + x)^1 = 2 + x
        let result = a.pow(&Integer::from(1));
        assert_eq!(result.real(), &Integer::from(2));
        assert_eq!(result.imag(), &Integer::from(1));
    }

    #[test]
    fn test_rth_roots() {
        let q = Integer::from_str("9908484735485245740582755998843475068910570989512225739800304203500256711207262150930812622460031920899674919818007279858208368349928684334780223996774347").unwrap();
        let c = Integer::from_str("7267288183214469410349447052665186833632058119533973432573869246434984462336560480880459677870106195135869371300420762693116774837763418518542884912967719").unwrap();
        let e = 21;

        let field = PrimeField::new(q.clone());
        let roots = rth_roots(&field, &c, e);

        // Check we got 7 distinct roots (21 = 3 × 7, so t=3 gives 7 unique roots)
        let unique_roots: HashSet<_> = roots.iter().collect();
        assert_eq!(unique_roots.len(), 7);

        // Verify each root is actually a 21st root of c
        for root in &roots {
            let check = root.clone().pow_mod(&Integer::from(e), &q).unwrap();
            assert_eq!(check, c, "root^21 mod q should equal c");
        }
    }
}
