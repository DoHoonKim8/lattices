use anyhow::Error;
use plonky2::{
    field::{extension::Extendable, types::PrimeField64},
    hash::hash_types::RichField,
    iop::{
        generator::{GeneratedValues, SimpleGenerator},
        target::Target,
        witness::PartitionWitness,
    },
    plonk::circuit_data::CommonCircuitData,
    util::serialization::{Buffer, IoResult},
};

use crate::vbfv::assigned::{AssignedNTTPoly, AssignedRelinearizationKey};

#[derive(Debug)]
struct RelinearizationGenerator<
    F: RichField + Extendable<D>,
    const D: usize,
    const N: usize,
    const Q: u64,
> {
    degree_2_ct: [AssignedNTTPoly<F, D, N, Q>; 3],
    degree_1_ct: [AssignedNTTPoly<F, D, N, Q>; 2],
    rlk: AssignedRelinearizationKey<F, D, N, Q>,
}

impl<F: PrimeField64 + RichField + Extendable<D>, const D: usize, const N: usize, const Q: u64>
    SimpleGenerator<F, D> for RelinearizationGenerator<F, D, N, Q>
{
    fn id(&self) -> String {
        "RelinearizationGenerator".to_string()
    }

    fn dependencies(&self) -> Vec<Target> {
        todo!()
    }

    fn run_once(
        &self,
        witness: &PartitionWitness<F>,
        out_buffer: &mut GeneratedValues<F>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn serialize(&self, dst: &mut Vec<u8>, common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        todo!()
    }

    fn deserialize(src: &mut Buffer, common_data: &CommonCircuitData<F, D>) -> IoResult<Self>
    where
        Self: Sized,
    {
        todo!()
    }
}
