use std::{iter::once, marker::PhantomData, ops::Add};

use anyhow::{Error, Result};
use itertools::chain;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        generator::{GeneratedValues, SimpleGenerator},
        target::{BoolTarget, Target},
        witness::{PartitionWitness, Witness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, circuit_data::CommonCircuitData},
    util::serialization::{Buffer, IoResult, Write},
};

use super::assigned::AssignedValue;

#[derive(Debug)]
enum ArithmeticOpKind<F: RichField + Extendable<D>, const D: usize, const Q: u64> {
    Add(AssignedValue<F, D, Q>, AssignedValue<F, D, Q>),
    Sub(AssignedValue<F, D, Q>, AssignedValue<F, D, Q>),
    Mul(AssignedValue<F, D, Q>, AssignedValue<F, D, Q>),
    MulConst(F, AssignedValue<F, D, Q>),
}

#[derive(Debug)]
struct ArithmeticOpsGenerator<F: RichField + Extendable<D>, const D: usize, const Q: u64> {
    quotient: AssignedValue<F, D, Q>,
    op_kind: ArithmeticOpKind<F, D, Q>,
}

impl<F: RichField + Extendable<D>, const D: usize, const Q: u64> ArithmeticOpsGenerator<F, D, Q> {
    fn new(quotient: AssignedValue<F, D, Q>, op_kind: ArithmeticOpKind<F, D, Q>) -> Self {
        Self { quotient, op_kind }
    }
}

impl<F: RichField + Extendable<D>, const D: usize, const Q: u64> SimpleGenerator<F, D>
    for ArithmeticOpsGenerator<F, D, Q>
{
    fn id(&self) -> String {
        "ArithmeticOpsGenerator".to_string()
    }

    fn dependencies(&self) -> Vec<Target> {
        let dependencies = match self.op_kind {
            ArithmeticOpKind::Add(x, y) | ArithmeticOpKind::Sub(x, y) | ArithmeticOpKind::Mul(x, y) => {
                [x.value, y.value].to_vec()
            }
            ArithmeticOpKind::MulConst(_, x) => vec![x.value],
        };
        dependencies
    }

    fn run_once(
        &self,
        witness: &PartitionWitness<F>,
        out_buffer: &mut GeneratedValues<F>,
    ) -> Result<()> {
        let tmp = match self.op_kind {
            ArithmeticOpKind::Add(x, y) => {
                let x = witness.get_target(x.value);
                let y = witness.get_target(y.value);
                (x.to_canonical_u64() as u128) + (y.to_canonical_u64() as u128)
            }
            ArithmeticOpKind::Sub(x, y) => {
                let x = witness.get_target(x.value);
                let y = witness.get_target(y.value);
                (x.to_canonical_u64() as u128) + (Q as u128) - (y.to_canonical_u64() as u128)
            }
            ArithmeticOpKind::Mul(x, y) => {
                let x = witness.get_target(x.value);
                let y = witness.get_target(y.value);
                (x.to_canonical_u64() as u128) * (y.to_canonical_u64() as u128)
            }
            ArithmeticOpKind::MulConst(constant, x) => {
                let x = witness.get_target(x.value);
                (constant.to_canonical_u64() as u128) * (x.to_canonical_u64() as u128)
            }
        };
        let quotient = tmp.div_euclid(Q as u128) as u64;
        out_buffer.set_target(self.quotient.value, F::from_canonical_u64(quotient))
    }

    fn serialize(&self, dst: &mut Vec<u8>, common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        let dependencies = self.dependencies();
        dependencies
            .into_iter()
            .chain(once(self.quotient.value))
            .map(|target| dst.write_target(target))
            .collect::<IoResult<()>>()
    }

    fn deserialize(src: &mut Buffer, common_data: &CommonCircuitData<F, D>) -> IoResult<Self>
    where
        Self: Sized,
    {
        todo!()
    }
}

/// `ArithmeticChip` is constraint builder for arithmetic operations between `\mathbb{Z}_Q` elements
pub(crate) struct ArithmeticChip<F: RichField + Extendable<D>, const D: usize, const Q: u64> {
    _marker: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize, const Q: u64> ArithmeticChip<F, D, Q> {
    pub(crate) fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    pub(crate) fn add(
        &self,
        cb: &mut CircuitBuilder<F, D>,
        x: AssignedValue<F, D, Q>,
        y: AssignedValue<F, D, Q>,
    ) -> Result<AssignedValue<F, D, Q>, Error> {
        let quotient = AssignedValue::new(cb);
        let op_kind = ArithmeticOpKind::Add(x, y);
        let arithmetic_ops_generator = ArithmeticOpsGenerator::new(quotient, op_kind);
        cb.add_simple_generator(arithmetic_ops_generator);

        let ring_modulus = F::from_canonical_u64(Q);
        let one = F::ONE;
        let neg_one = cb.neg_one();
        let tmp = cb.add(x.value, y.value);
        let result = cb.arithmetic(ring_modulus, one, neg_one, quotient.value, tmp);
        Ok(AssignedValue::new_from_target(cb, result))
    }

    pub(crate) fn sub(
        &self,
        cb: &mut CircuitBuilder<F, D>,
        x: AssignedValue<F, D, Q>,
        y: AssignedValue<F, D, Q>,
    ) -> Result<AssignedValue<F, D, Q>, Error> {
        let quotient = AssignedValue::new(cb);
        let op_kind = ArithmeticOpKind::Sub(x, y);
        let arithmetic_ops_generator = ArithmeticOpsGenerator::new(quotient, op_kind);
        cb.add_simple_generator(arithmetic_ops_generator);

        let ring_modulus = F::from_canonical_u64(Q);
        let one = F::ONE;
        let neg_one = cb.neg_one();
        let mut tmp = cb.add_const(x.value, ring_modulus);
        tmp = cb.sub(tmp, y.value);
        let result = cb.arithmetic(ring_modulus, one, neg_one, quotient.value, tmp);
        Ok(AssignedValue::new_from_target(cb, result))
    }

    pub(crate) fn mul_with_constant(
        &self,
        cb: &mut CircuitBuilder<F, D>,
        multiplicand: AssignedValue<F, D, Q>,
        constant: F,
    ) -> Result<AssignedValue<F, D, Q>, Error> {
        let quotient = AssignedValue::new(cb);
        let op_kind = ArithmeticOpKind::MulConst(constant, multiplicand);
        let arithmetic_ops_generator = ArithmeticOpsGenerator::new(quotient, op_kind);
        cb.add_simple_generator(arithmetic_ops_generator);

        let ring_modulus = F::from_canonical_u64(Q);
        let one = F::ONE;
        let neg_one = cb.neg_one();
        let tmp = cb.mul_const(constant, multiplicand.value);
        let result = cb.arithmetic(ring_modulus, one, neg_one, quotient.value, tmp);
        Ok(AssignedValue::new_from_target(cb, result))
    }
}
