use std::marker::PhantomData;

use crate::{bfv::Ciphertext, vbfv::assigned::AssignedValue};
use anyhow::{Error, Ok, Result};
use itertools::Itertools;
use plonky2::{
    field::{extension::Extendable, types::PrimeField64},
    hash::hash_types::RichField,
    iop::{
        generator::{GeneratedValues, SimpleGenerator},
        target::{BoolTarget, Target},
        witness::{PartialWitness, PartitionWitness, Witness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, circuit_data::CommonCircuitData},
    util::serialization::{Buffer, IoResult, Read, Write},
};

use super::{arithmetic_chip::ArithmeticChip, assigned::AssignedCiphertext};

// TODO : AddConst, Mul, MulConst
#[derive(Debug)]
struct CiphertextOpsGenerator<
    F: RichField + Extendable<D>,
    const D: usize,
    const N: usize,
    const Q: u64,
> {
    ct0: AssignedCiphertext<F, D, N, Q>,
    ct1: AssignedCiphertext<F, D, N, Q>,
    quotient: Vec<AssignedValue<F, D, Q>>,
}

impl<F: PrimeField64 + RichField + Extendable<D>, const D: usize, const N: usize, const Q: u64>
    CiphertextOpsGenerator<F, D, N, Q>
{
    fn new(
        cb: &mut CircuitBuilder<F, D>,
        ct0: AssignedCiphertext<F, D, N, Q>,
        ct1: AssignedCiphertext<F, D, N, Q>,
        quotient: Vec<AssignedValue<F, D, Q>>,
    ) -> Self {
        Self { ct0, ct1, quotient }
    }
}

impl<F: PrimeField64 + RichField + Extendable<D>, const D: usize, const N: usize, const Q: u64>
    SimpleGenerator<F, D> for CiphertextOpsGenerator<F, D, N, Q>
{
    fn id(&self) -> String {
        "CiphertextOpsGenerator".to_string()
    }

    fn dependencies(&self) -> Vec<Target> {
        let mut targets = self.ct0.ciphertext_targets();
        targets.extend_from_slice(self.ct1.ciphertext_targets().as_ref());
        targets
    }

    fn run_once(
        &self,
        witness: &PartitionWitness<F>,
        out_buffer: &mut GeneratedValues<F>,
    ) -> Result<(), Error> {
        let dependencies = self.dependencies();
        let (ct0_targets, ct1_targets) = dependencies.split_at(dependencies.len() / 2);
        for (i, (ct0_target, ct1_target)) in ct0_targets.iter().zip(ct1_targets).enumerate() {
            let ct0_eval = witness.get_target(*ct0_target);
            let ct1_eval = witness.get_target(*ct1_target);
            let tmp = ct0_eval.to_canonical_u64() + ct1_eval.to_canonical_u64();
            let quotient = tmp.div_euclid(Q);
            out_buffer.set_target(self.quotient[i].value, F::from_canonical_u64(quotient));
        }
        Ok(())
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        self.dependencies()
            .iter()
            .map(|target| dst.write_target(*target))
            .collect::<IoResult<Vec<_>>>()?;
        self.quotient
            .iter()
            .map(|q| dst.write_target(q.value))
            .collect::<IoResult<()>>()
    }

    fn deserialize(src: &mut Buffer, common_data: &CommonCircuitData<F, D>) -> IoResult<Self>
    where
        Self: Sized,
    {
        todo!()
    }
}

/// `CiphertextChip` is contraint builder for arithmetic operations between bfv ciphertexts
struct CiphertextChip<F: RichField + Extendable<D>, const D: usize, const N: usize, const Q: u64> {
    arithmetic_chip: ArithmeticChip<F, D, Q>,
}

impl<F: RichField + Extendable<D>, const D: usize, const N: usize, const Q: u64>
    CiphertextChip<F, D, N, Q>
{
    pub fn new() -> Self {
        Self {
            arithmetic_chip: ArithmeticChip::new(),
        }
    }

    /// Assigns bfv ciphertexts and constrains the correct formulation of ciphertexts
    /// Expects input ciphertext is not in NTT form
    pub fn assign_ciphertexts(
        pw: &mut PartialWitness<F>,
        ct: &Vec<Ciphertext>,
    ) -> Result<Vec<AssignedCiphertext<F, D, N, Q>>, Error> {
        todo!()
    }

    pub fn add_ciphertexts(
        &self,
        cb: &mut CircuitBuilder<F, D>,
        ct0: AssignedCiphertext<F, D, N, Q>,
        ct1: AssignedCiphertext<F, D, N, Q>,
    ) -> Result<AssignedCiphertext<F, D, N, Q>, Error> {
        let mut ct_result_values = vec![];
        let quotient = (0..2 * N)
            .map(|_| AssignedValue::new(cb))
            .into_iter()
            .collect_vec();
        let ring_modulus = F::from_canonical_u64(Q);
        let one = F::ONE;
        let neg_one = cb.neg_one();
        let ciphertext_ops_generator = CiphertextOpsGenerator::new(cb, ct0, ct1, quotient.clone());
        cb.add_simple_generator(ciphertext_ops_generator);
        for (i, (ct0_value, ct1_value)) in ct0.values().iter().zip(ct1.values().iter()).enumerate()
        {
            let ct_added = self.arithmetic_chip.add(cb, *ct0_value, *ct1_value)?;
            ct_result_values.push(ct_added);
        }
        let (ct_result_0_values, ct_result_1_values) = ct_result_values.split_at(N);
        let ct_result = AssignedCiphertext::new_from_values(
            ct_result_0_values.try_into().unwrap(),
            ct_result_1_values.try_into().unwrap(),
        );
        Ok(ct_result)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::{Error, Ok, Result};
    use itertools::Itertools;
    use plonky2::{
        field::{
            extension::Extendable,
            goldilocks_field::GoldilocksField,
            types::{Field, Field64, PrimeField64},
        },
        hash::hash_types::RichField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use rand::SeedableRng;

    use crate::{
        bfv::{Plaintext, SecretKey},
        vbfv::{assigned::AssignedCiphertext, ciphertext_chip::CiphertextChip, ntt_forward},
    };

    #[test]
    fn test_add_ciphertexts() -> Result<(), Error> {
        const D: usize = 2;
        const N: usize = 8;
        const Q: u64 = 3329;
        type C = PoseidonGoldilocksConfig;
        type F = GoldilocksField;
        for t in vec![2, 4, 8, 16, 32].iter() {
            let msg_1 = vec![0, 1, 2, 3, 4, 5, 6, 7];
            let msg_2 = vec![7, 6, 5, 4, 3, 2, 1, 0];
            let std_dev = 3.2;
            // Prepare ciphertexts
            let mut rng = rand::rngs::StdRng::seed_from_u64(19);

            let secret_key = SecretKey::generate(N, &mut rng);
            let public_key = secret_key.public_key_gen(Q as i64, std_dev, &mut rng);

            let plaintext1 = Plaintext::new(msg_1, *t);
            let ciphertext1 = plaintext1.encrypt(&public_key, std_dev, &mut rng);
            let decrypted1 = ciphertext1.decrypt(&secret_key);
            assert_eq!(decrypted1.poly(), plaintext1.poly() % (*t, N));

            let plaintext2 = Plaintext::new(msg_2, *t);
            let ciphertext2 = plaintext2.encrypt(&public_key, std_dev, &mut rng);
            let decrypted2 = ciphertext2.decrypt(&secret_key);
            assert_eq!(decrypted2.poly(), plaintext2.poly() % (*t, N));

            let add_ciphertext = ciphertext1.clone() + ciphertext2.clone();

            // constrain adding ciphertexts
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<<C as GenericConfig<D>>::F, D>::new(config);
            let ciphertext_chip = CiphertextChip::new();

            let assigned_ct1 = AssignedCiphertext::<F, D, N, Q>::new(&mut builder);
            let assigned_ct2 = AssignedCiphertext::<F, D, N, Q>::new(&mut builder);
            let assigned_ct_added =
                ciphertext_chip.add_ciphertexts(&mut builder, assigned_ct1, assigned_ct2)?;

            assigned_ct_added.register_as_public_input(&mut builder);

            // assign witnesses
            let mut pw = PartialWitness::new();
            assigned_ct1.assign(&mut pw, ciphertext1)?;
            assigned_ct2.assign(&mut pw, ciphertext2)?;

            let data = builder.build::<C>();
            let proof = data.prove(pw)?;

            let add_ciphertext = add_ciphertext
                .c_0
                .val()
                .to_owned()
                .into_iter()
                .chain(add_ciphertext.c_1.val().to_owned().into_iter())
                .map(|coeff| F::from_canonical_i64(coeff))
                .collect_vec();
            let (add_ciphertext_0, add_ciphertext_1) = add_ciphertext.split_at(N);
            let expected_0 = ntt_forward::<F, D, Q>(add_ciphertext_0);
            let expected_1 = ntt_forward::<F, D, Q>(add_ciphertext_1);
            let expected = expected_0
                .into_iter()
                .chain(expected_1.into_iter())
                .collect_vec();
            proof
                .public_inputs
                .iter()
                .zip_eq(expected)
                .for_each(|(actual, expected)| {
                    assert_eq!(*actual, expected);
                });

            data.verify(proof)?;
        }
        Ok(())
    }
}
