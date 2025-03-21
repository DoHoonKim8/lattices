use std::marker::PhantomData;

use crate::bfv::Ciphertext;
use anyhow::{Error, Result};
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::witness::PartialWitness,
    plonk::circuit_builder::CircuitBuilder,
};

use super::assigned::AssignedCiphertext;

/// `ArithmeticChip` is contraint builder for arithmetic operations between bfv ciphertexts
struct ArithmeticChip<F: RichField + Extendable<D>, const D: usize, const N: usize, const Q: usize>
{
    _marker: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize, const N: usize, const Q: usize>
    ArithmeticChip<F, D, N, Q>
{
    /// Assigns bfv ciphertext and constrains the correct formulation of ciphertext
    /// Expects input ciphertext is not in NTT form
    pub fn assign_ciphertext(
        pw: PartialWitness<F>,
        ct: Ciphertext,
    ) -> Result<AssignedCiphertext<F, D, N, Q>, Error> {
        // Return `AssignedCiphertext`
        todo!()
    }

    pub fn add_ciphertexts(
        cb: CircuitBuilder<F, D>,
        ct0: AssignedCiphertext<F, D, N, Q>,
        ct1: AssignedCiphertext<F, D, N, Q>,
    ) -> Result<AssignedCiphertext<F, D, N, Q>, Error> {
        todo!()
    }
}
