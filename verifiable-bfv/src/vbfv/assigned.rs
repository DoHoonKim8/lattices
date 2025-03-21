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
    util::log2_strict,
};

use super::ntt_chip::NTTChip;
use crate::{bfv::Ciphertext, vbfv::ntt_forward};

/// `AssignedPoly` is assigned value of polynomial inside `R_Q = \mathbb{Z}_Q[X]/(X^N+1)`
/// where `X^N+1` is `2N`-th cyclotomic polynomial(N is power-of-two).
struct AssignedPoly<F: RichField + Extendable<D>, const D: usize, const N: usize, const Q: usize> {
    _marker: PhantomData<F>,
    coeffs: [Target; N],
}

impl<F: RichField + Extendable<D>, const D: usize, const N: usize, const Q: usize>
    AssignedPoly<F, D, N, Q>
{
    fn new(cb: &mut CircuitBuilder<F, D>) -> Result<Self, Error> {
        Ok(AssignedPoly {
            _marker: PhantomData,
            coeffs: cb.add_virtual_targets(N).try_into().unwrap(),
        })
    }

    fn assign(&self, pw: &mut PartialWitness<F>, coeffs: &Vec<i64>) -> Result<(), Error> {
        // sanity check for the input
        assert_eq!(coeffs.len(), N);
        self.coeffs
            .iter()
            .zip(coeffs)
            .map(|(tcoeff, coeff)| pw.set_target(*tcoeff, F::from_canonical_i64(*coeff)))
            .collect::<Result<Vec<()>, Error>>()?;
        Ok(())
    }
}

/// `AssignedNTTPoly` is assigned value of polynomial inside `R_Q = \mathbb{Z}_Q[X]/(X^N+1)`
/// where `X^N+1` is `2N`-th cyclotomic polynomial(N is power-of-two).
/// In bfv, we will assume that `Q-1` is divisible by `2N`, which means that `X^N+1` is fully
/// splitting in `\mathbb{Z}_Q`.
/// `AssignedNTTPoly` should be created from `AssignedPoly`.
struct AssignedNTTPoly<F: RichField + Extendable<D>, const D: usize, const N: usize, const Q: usize>
{
    _marker: PhantomData<F>,
    evals: [Target; N],
}

impl<F: RichField + Extendable<D>, const D: usize, const N: usize, const Q: usize>
    AssignedNTTPoly<F, D, N, Q>
{
    fn new(
        cb: &mut CircuitBuilder<F, D>,
        assigned_poly: &AssignedPoly<F, D, N, Q>,
    ) -> Result<Self, Error> {
        Ok(AssignedNTTPoly {
            _marker: PhantomData,
            evals: NTTChip::ntt_forward(cb, &assigned_poly.coeffs.to_vec())
                .try_into()
                .unwrap(),
        })
    }

    /// Converts polynomial in coefficients form into NTT form and then assign
    fn assign(&self, pw: &mut PartialWitness<F>, poly_coeffs: &Vec<i64>) -> Result<(), Error> {
        let evals = ntt_forward(
            &poly_coeffs
                .iter()
                .map(|coeff| F::from_canonical_i64(*coeff))
                .collect_vec(),
        );
        self.evals
            .iter()
            .zip(evals)
            .map(|(teval, eval)| pw.set_target(*teval, eval))
            .collect::<Result<Vec<()>, Error>>()?;
        Ok(())
    }

    fn add(&self, cb: &mut CircuitBuilder<F, D>, other: Self) -> Result<Self, Error> {
        todo!()
    }

    fn mul(&self, cb: &mut CircuitBuilder<F, D>, other: Self) -> Result<Self, Error> {
        todo!()
    }
}

/// `AssignedCiphertext` is assigned value of bfv ciphertext consisting of two `R_Q` polynomials.
/// `ciphertext` --- NTT ---> `ntt_ciphertext`
pub struct AssignedCiphertext<
    F: RichField + Extendable<D>,
    const D: usize,
    const N: usize,
    const Q: usize,
> {
    ciphertext: [AssignedPoly<F, D, N, Q>; 2],
    ntt_ciphertext: [AssignedNTTPoly<F, D, N, Q>; 2],
}

impl<F: RichField + Extendable<D>, const D: usize, const N: usize, const Q: usize>
    AssignedCiphertext<F, D, N, Q>
{
    fn new(cb: &mut CircuitBuilder<F, D>) -> Result<Self, Error> {
        let ct_0 = AssignedPoly::new(cb)?;
        let ct_1 = AssignedPoly::new(cb)?;
        let ntt_ct_0 = AssignedNTTPoly::new(cb, &ct_0)?;
        let ntt_ct_1 = AssignedNTTPoly::new(cb, &ct_1)?;
        Ok(AssignedCiphertext {
            ciphertext: [ct_0, ct_1],
            ntt_ciphertext: [ntt_ct_0, ntt_ct_1],
        })
    }

    fn assign(&self, pw: &mut PartialWitness<F>, ct: Ciphertext) -> Result<(), Error> {
        // Assigns ciphertext into 2 * `AssignedPoly`
        self.ciphertext[0].assign(pw, ct.c_0.val())?;
        self.ciphertext[1].assign(pw, ct.c_1.val())?;
        self.ntt_ciphertext[0].assign(pw, ct.c_0.val())?;
        self.ntt_ciphertext[1].assign(pw, ct.c_1.val())?;
        Ok(())
    }
}
