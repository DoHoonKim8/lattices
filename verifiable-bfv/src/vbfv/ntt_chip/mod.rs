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
    arithmetic_chip: ArithmeticChip<F, D, Q>,
}

impl<F: RichField + Extendable<D>, const D: usize, const Q: u64> NTTChip<F, D, Q> {
    pub fn new(arithmetic_chip: ArithmeticChip<F, D, Q>) -> Self {
        Self { arithmetic_chip }
    }

    pub fn ntt_forward(
        &mut self,
        input: &Vec<AssignedValue<F, D, Q>>,
    ) -> Result<Vec<AssignedValue<F, D, Q>>, Error> {
        let mut current = input.clone();
        for m in (0..params::LOGN).map(|i| 2usize.pow(i)) {
            current = self.ntt_fw_update(&current, m)?;
        }

        Ok(current)
    }

    fn ntt_fw_update(
        &mut self,
        input: &Vec<AssignedValue<F, D, Q>>,
        m: usize,
    ) -> Result<Vec<AssignedValue<F, D, Q>>, Error> {
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
                let v = self.arithmetic_chip.mul_with_constant(a[j + t], root)?;
                // a[j] = cb.add(u, v);
                a[j] = self.arithmetic_chip.add(u, v)?;
                // a[j + t] = cb.sub(u, v);
                a[j + t] = self.arithmetic_chip.sub(u, v)?;
            }
        }
        Ok(a)
    }

    pub fn ntt_backward(
        &mut self,
        input: &Vec<AssignedValue<F, D, Q>>,
    ) -> Result<Vec<AssignedValue<F, D, Q>>, Error> {
        let mut current = input.clone();
        for m in (0..params::LOGN).rev().map(|i| 2usize.pow(i)) {
            current = self.ntt_bw_update(&current, m)?;
        }
        // let n_inv = cb.constant(F::from_canonical_u64(params::NINV));
        let n_inv = F::from_canonical_u64(params::NINV);
        current
            .into_iter()
            .map(|g| self.arithmetic_chip.mul_with_constant(g, n_inv))
            .collect::<Result<Vec<_>, Error>>()
    }

    fn ntt_bw_update(
        &mut self,
        input: &Vec<AssignedValue<F, D, Q>>,
        m: usize,
    ) -> Result<Vec<AssignedValue<F, D, Q>>, Error> {
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
                a[j] = self.arithmetic_chip.add(u, v)?;
                // let w = cb.sub(u, v);
                let w = self.arithmetic_chip.sub(u, v)?;
                // a[j + t] = cb.mul(w, s);
                a[j + t] = self.arithmetic_chip.mul_with_constant(w, root)?;
            }
            j1 += 2 * t;
        }
        Ok(a)
    }
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
        const Q: u64 = 3329;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let N = params::N;

        let config = CircuitConfig::standard_recursion_config();
        let builder = CircuitBuilder::<F, D>::new(config);
        let arithmetic_chip = ArithmeticChip::new(builder);
        let mut ntt_chip = NTTChip::<F, D, Q>::new(arithmetic_chip);
        let x = (0..N)
            .map(|_| AssignedValue::<F, D, Q>::new(&mut builder))
            .collect_vec();

        let z = ntt_chip.ntt_forward(&mut builder, &x).unwrap();
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
        const Q: u64 = 3329;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let N = params::N;

        let config = CircuitConfig::standard_recursion_config();
        let builder = CircuitBuilder::<F, D>::new(config);
        let arithmetic_chip = ArithmeticChip::new(builder);
        let mut ntt_chip = NTTChip::<F, D, Q>::new(arithmetic_chip);
        let x = (0..N)
            .map(|_| AssignedValue::<F, D, Q>::new(&mut builder))
            .collect_vec();

        let z = ntt_chip.ntt_backward(&mut builder, &x).unwrap();
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
