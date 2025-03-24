use std::marker::PhantomData;

use crate::ntt_params::params;
use anyhow::Error;
/// Copied from https://github.com/zama-ai/verifiable-fhe-paper/blob/main/src/ntt/mod.rs
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use super::arithmetic_chip::ArithmeticChip;
use super::assigned::AssignedValue;

pub(crate) struct NTTChip<F: RichField + Extendable<D>, const D: usize, const Q: u64> {
    _marker: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize, const Q: u64> NTTChip<F, D, Q> {
    pub fn ntt_forward(
        cb: &mut CircuitBuilder<F, D>,
        input: &Vec<AssignedValue<F, D, Q>>,
    ) -> Result<Vec<AssignedValue<F, D, Q>>, Error> {
        let mut current = input.clone();
        for m in (0..params::LOGN).map(|i| 2usize.pow(i)) {
            current = ntt_fw_update(cb, &current, m)?;
        }

        Ok(current)
    }

    pub fn ntt_backward(
        cb: &mut CircuitBuilder<F, D>,
        input: &Vec<AssignedValue<F, D, Q>>,
    ) -> Result<Vec<AssignedValue<F, D, Q>>, Error> {
        let mut current = input.clone();
        for m in (0..params::LOGN).rev().map(|i| 2usize.pow(i)) {
            current = ntt_bw_update(cb, &current, m)?;
        }

        let arithmetic_chip = ArithmeticChip::new();
        // let n_inv = cb.constant(F::from_canonical_u64(params::NINV));
        let n_inv = F::from_canonical_u64(params::NINV);
        current
            .into_iter()
            .map(|g| arithmetic_chip.mul_with_constant(cb, g, n_inv))
            .collect::<Result<Vec<_>, Error>>()
    }
}

fn ntt_fw_update<F: RichField + Extendable<D>, const D: usize, const Q: u64>(
    cb: &mut CircuitBuilder<F, D>,
    input: &Vec<AssignedValue<F, D, Q>>,
    m: usize,
) -> Result<Vec<AssignedValue<F, D, Q>>, Error> {
    let arithmetic_chip = ArithmeticChip::new();
    let mut a = input.clone();
    let t = params::N / (2 * m);
    for i in 0..m {
        let j1 = 2 * i * t;
        let j2 = j1 + t;
        let root = F::from_canonical_u64(params::ROOTS[m + i]);
        // let s = cb.constant(F::from_canonical_u64(root));
        for j in j1..j2 {
            let u = a[j];
            // let v = cb.mul(a[j + t], s);
            let v = arithmetic_chip.mul_with_constant(cb, a[j + t], root)?;
            // a[j] = cb.add(u, v);
            a[j] = arithmetic_chip.add(cb, u, v)?;
            // a[j + t] = cb.sub(u, v);
            a[j + t] = arithmetic_chip.sub(cb, u, v)?;
        }
    }
    Ok(a)
}

fn ntt_bw_update<F: RichField + Extendable<D>, const D: usize, const Q: u64>(
    cb: &mut CircuitBuilder<F, D>,
    input: &Vec<AssignedValue<F, D, Q>>,
    m: usize,
) -> Result<Vec<AssignedValue<F, D, Q>>, Error> {
    let arithmetic_chip = ArithmeticChip::new();
    let mut a = input.clone();
    let t = params::N / (2 * m);
    let mut j1 = 0usize;
    for i in 0..m {
        let j2 = j1 + t;
        let root = F::from_canonical_u64(params::INVROOTS[m + i]);
        // let s = cb.constant(F::from_canonical_u64(root));
        for j in j1..j2 {
            let u = a[j];
            let v = a[j + t];
            // a[j] = cb.add(u, v);
            a[j] = arithmetic_chip.add(cb, u, v)?;
            // let w = cb.sub(u, v);
            let w = arithmetic_chip.sub(cb, u, v)?;
            // a[j + t] = cb.mul(w, s);
            a[j + t] = arithmetic_chip.mul_with_constant(cb, w, root)?;
        }
        j1 += 2 * t;
    }
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;
    use plonky2::field::types::Field;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    #[test]
    fn test_ntt_forward() {
        const D: usize = 2;
        const Q: u64 = 97;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let N = params::N;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let x = (0..N)
            .map(|_| AssignedValue::<F, D, Q>::new(&mut builder))
            .collect_vec();

        let z = NTTChip::ntt_forward(&mut builder, &x).unwrap();
        x.iter()
            .for_each(|x| x.register_as_public_input(&mut builder));
        z.iter()
            .for_each(|z| z.register_as_public_input(&mut builder));
        let mut pw = PartialWitness::new();
        x.iter()
            .zip(&params::TESTG)
            .map(|(x, g)| x.assign(&mut pw, F::from_canonical_u64(*g)))
            .collect::<Result<Vec<_>, Error>>()
            .unwrap();

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        let out = &proof.public_inputs[N..2 * N];

        for (&actual, expected) in out.into_iter().zip(params::TESTGHAT) {
            assert_eq!(actual, F::from_canonical_u64(expected));
        }

        let _ = data.verify(proof).unwrap();
    }

    #[test]
    fn test_ntt_backward() {
        const D: usize = 2;
        const Q: u64 = 97;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let N = params::N;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let x = (0..N)
            .map(|_| AssignedValue::<F, D, Q>::new(&mut builder))
            .collect_vec();

        let z = NTTChip::ntt_backward(&mut builder, &x).unwrap();
        // Public inputs are the initial value (provided below) and the result (which is generated).
        x.iter()
            .for_each(|x| x.register_as_public_input(&mut builder));
        z.iter()
            .for_each(|z| z.register_as_public_input(&mut builder));
        let mut pw = PartialWitness::new();
        x.iter()
            .zip(&params::TESTGHAT)
            .map(|(x, g)| x.assign(&mut pw, F::from_canonical_u64(*g)))
            .collect::<Result<Vec<_>, Error>>()
            .unwrap();

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        let out = &proof.public_inputs[N..2 * N];

        for (&actual, expected) in out.into_iter().zip(params::TESTG) {
            assert_eq!(actual, F::from_canonical_u64(expected));
        }

        let _ = data.verify(proof).unwrap();
    }
}
