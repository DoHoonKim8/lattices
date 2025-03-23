use crate::ntt_params::params;
use anyhow::{Error, Result};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};

mod arithmetic_chip;
mod assigned;
mod ntt_chip;

fn ntt_fw_update<F: RichField + Extendable<D>, const D: usize, const Q: u64>(input: &[F], m: usize) -> Vec<F> {
    let mut a = input.to_vec();
    let t = params::N / (2 * m);
    for i in 0..m {
        let j1 = 2 * i * t;
        let j2 = j1 + t;
        let root = params::ROOTS[m + i];
        let s = F::from_canonical_u64(root);
        for j in j1..j2 {
            let u = a[j];
            let v = F::from_canonical_u64((a[j + t] * s).to_canonical_u64() % Q);
            a[j] = F::from_canonical_u64((u + v).to_canonical_u64() % Q);
            a[j + t] = F::from_canonical_u64((u - v).to_canonical_u64() % Q);
        }
    }
    a
}

pub fn ntt_forward<F: RichField + Extendable<D>, const D: usize, const Q: u64>(input: &[F]) -> Vec<F> {
    let mut current = input.to_vec();
    for m in (0..params::LOGN).map(|i| 2usize.pow(i)) {
        current = ntt_fw_update::<F, D, Q>(&current, m);
    }

    current
}

pub fn prove_bfv_ops() -> Result<(), Error> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    todo!()
}
