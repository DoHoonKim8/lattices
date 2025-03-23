use std::marker::PhantomData;

use anyhow::Error;
use itertools::Itertools;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
    util::{log2_ceil, log2_strict},
};

use super::ntt_chip::NTTChip;
use crate::{bfv::Ciphertext, vbfv::ntt_forward};

/// `AssignedValue` is assigned value of mod `Q` element
#[derive(Copy, Clone, Debug)]
pub(crate) struct AssignedValue<F: RichField + Extendable<D>, const D: usize, const Q: u64> {
    _marker: PhantomData<F>,
    pub value: Target,
}

impl<F: RichField + Extendable<D>, const D: usize, const Q: u64> AssignedValue<F, D, Q> {
    pub fn new(cb: &mut CircuitBuilder<F, D>) -> Self {
        let value = cb.add_virtual_target();
        cb.range_check(value, log2_ceil(Q as usize));
        Self {
            _marker: PhantomData,
            value,
        }
    }

    pub fn new_from_target(cb: &mut CircuitBuilder<F, D>, target: Target) -> Self {
        cb.range_check(target, log2_ceil(Q as usize));
        Self {
            _marker: PhantomData,
            value: target,
        }
    }

    pub fn assign(&self, pw: &mut PartialWitness<F>, value: F) -> Result<(), Error> {
        pw.set_target(self.value, value)
    }
}

/// `AssignedPoly` is assigned value of polynomial inside `R_Q = \mathbb{Z}_Q[X]/(X^N+1)`
/// where `X^N+1` is `2N`-th cyclotomic polynomial(N is power-of-two).
#[derive(Copy, Clone, Debug)]
struct AssignedPoly<F: RichField + Extendable<D>, const D: usize, const N: usize, const Q: u64> {
    _marker: PhantomData<F>,
    coeffs: [AssignedValue<F, D, Q>; N],
}

impl<F: RichField + Extendable<D>, const D: usize, const N: usize, const Q: u64>
    AssignedPoly<F, D, N, Q>
{
    fn new(cb: &mut CircuitBuilder<F, D>) -> Result<Self, Error> {
        Ok(AssignedPoly {
            _marker: PhantomData,
            coeffs: [(); N].map(|_| AssignedValue::new(cb)),
        })
    }

    fn coeff_targets(&self) -> Vec<Target> {
        self.coeffs.iter().map(|coeff| coeff.value).collect_vec()
    }

    fn assign(&self, pw: &mut PartialWitness<F>, coeffs: &Vec<i64>) -> Result<(), Error> {
        // sanity check for the input
        assert_eq!(coeffs.len(), N);
        self.coeffs
            .iter()
            .zip(coeffs)
            .map(|(tcoeff, coeff)| tcoeff.assign(pw, F::from_canonical_i64(*coeff)))
            .collect::<Result<Vec<()>, Error>>()?;
        Ok(())
    }
}

/// `AssignedNTTPoly` is assigned value of polynomial inside `R_Q = \mathbb{Z}_Q[X]/(X^N+1)`
/// where `X^N+1` is `2N`-th cyclotomic polynomial(N is power-of-two).
/// In bfv, we will assume that `Q-1` is divisible by `2N`, which means that `X^N+1` is fully
/// splitting in `\mathbb{Z}_Q`.
/// `AssignedNTTPoly` should be created from `AssignedPoly`.
#[derive(Copy, Clone, Debug)]
struct AssignedNTTPoly<F: RichField + Extendable<D>, const D: usize, const N: usize, const Q: u64> {
    _marker: PhantomData<F>,
    evals: [AssignedValue<F, D, Q>; N],
}

impl<F: RichField + Extendable<D>, const D: usize, const N: usize, const Q: u64>
    AssignedNTTPoly<F, D, N, Q>
{
    fn new(cb: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            _marker: PhantomData,
            evals: [(); N].map(|_| AssignedValue::new(cb)),
        }
    }

    fn new_from_targets(cb: &mut CircuitBuilder<F, D>, evals: [Target; N]) -> Self {
        Self {
            _marker: PhantomData,
            evals: evals.map(|eval| AssignedValue::new_from_target(cb, eval)),
        }
    }

    /// Converts polynomial in coefficients form into NTT form and then assign
    fn assign(&self, pw: &mut PartialWitness<F>, poly_coeffs: &Vec<i64>) -> Result<(), Error> {
        println!("{:?}", poly_coeffs);
        let evals = ntt_forward(
            &poly_coeffs
                .iter()
                .map(|coeff| F::from_canonical_i64(*coeff))
                .collect_vec(),
        );
        let evals = evals.iter().map(|eval| F::from_canonical_u64(eval.to_canonical_u64() % Q)).collect_vec();
        println!("{:?}", evals);
        self.evals
            .iter()
            .zip(evals)
            .map(|(teval, eval)| teval.assign(pw, eval))
            .collect::<Result<Vec<()>, Error>>()?;
        Ok(())
    }
}

/// `AssignedCiphertext` is assigned value of bfv ciphertext consisting of two `R_Q` polynomials.
#[derive(Copy, Clone, Debug)]
pub struct AssignedCiphertext<
    F: RichField + Extendable<D>,
    const D: usize,
    const N: usize,
    const Q: u64,
> {
    ciphertext: [AssignedNTTPoly<F, D, N, Q>; 2],
}

impl<F: RichField + Extendable<D>, const D: usize, const N: usize, const Q: u64>
    AssignedCiphertext<F, D, N, Q>
{
    pub fn new(cb: &mut CircuitBuilder<F, D>) -> Self {
        let ct_0 = AssignedNTTPoly::new(cb);
        let ct_1 = AssignedNTTPoly::new(cb);
        AssignedCiphertext {
            ciphertext: [ct_0, ct_1],
        }
    }

    pub fn new_from_targets(
        cb: &mut CircuitBuilder<F, D>,
        ct_0_targets: [Target; N],
        ct_1_targets: [Target; N],
    ) -> Self {
        Self {
            ciphertext: [
                AssignedNTTPoly::new_from_targets(cb, ct_0_targets),
                AssignedNTTPoly::new_from_targets(cb, ct_1_targets),
            ],
        }
    }

    pub fn register_as_public_input(&self, cb: &mut CircuitBuilder<F, D>) {
        self.ciphertext[0].evals.iter().for_each(|eval| {
            cb.register_public_input(eval.value);
        });
        self.ciphertext[1].evals.iter().for_each(|eval| {
            cb.register_public_input(eval.value);
        });
    }

    pub(crate) fn ciphertext_targets(&self) -> Vec<Target> {
        self.ciphertext
            .iter()
            .flat_map(|ct| ct.evals.iter().map(|eval| eval.value).collect_vec())
            .collect_vec()
    }

    pub fn assign(&self, pw: &mut PartialWitness<F>, ct: Ciphertext) -> Result<(), Error> {
        self.ciphertext[0].assign(pw, ct.c_0.val())?;
        self.ciphertext[1].assign(pw, ct.c_1.val())?;
        Ok(())
    }
}
