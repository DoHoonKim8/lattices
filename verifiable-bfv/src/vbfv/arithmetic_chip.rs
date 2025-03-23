use std::marker::PhantomData;

use crate::{bfv::Ciphertext, vbfv::assigned::AssignedValue};
use anyhow::{Error, Ok, Result};
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

use super::assigned::AssignedCiphertext;

// TODO : AddConst, Mul, MulConst
#[derive(Debug)]
struct ArithmeticOpsGenerator<
    F: RichField + Extendable<D>,
    const D: usize,
    const N: usize,
    const Q: u64,
> {
    ct0: AssignedCiphertext<F, D, N, Q>,
    ct1: AssignedCiphertext<F, D, N, Q>,
    ct_result: AssignedCiphertext<F, D, N, Q>,
    quotient: Vec<AssignedValue<F, D, Q>>,
}

impl<F: PrimeField64 + RichField + Extendable<D>, const D: usize, const N: usize, const Q: u64>
    ArithmeticOpsGenerator<F, D, N, Q>
{
    fn new(
        cb: &mut CircuitBuilder<F, D>,
        ct0: AssignedCiphertext<F, D, N, Q>,
        ct1: AssignedCiphertext<F, D, N, Q>,
        ct_result: AssignedCiphertext<F, D, N, Q>,
        quotient: Vec<AssignedValue<F, D, Q>>,
    ) -> Self {
        Self {
            ct0,
            ct1,
            ct_result,
            quotient,
        }
    }
}

impl<F: PrimeField64 + RichField + Extendable<D>, const D: usize, const N: usize, const Q: u64>
    SimpleGenerator<F, D> for ArithmeticOpsGenerator<F, D, N, Q>
{
    fn id(&self) -> String {
        "ArithmeticOpsGenerator".to_string()
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
        let ct_result_targets = self.ct_result.ciphertext_targets();
        for (i, (ct0_target, ct1_target)) in ct0_targets.iter().zip(ct1_targets).enumerate() {
            let ct0_eval = witness.get_target(*ct0_target);
            let ct1_eval = witness.get_target(*ct1_target);
            let tmp = ct0_eval.to_canonical_u64() + ct1_eval.to_canonical_u64();
            let quotient = tmp.div_euclid(Q);
            let remainder = tmp.rem_euclid(Q);
            out_buffer.set_target(self.quotient[i].value, F::from_canonical_u64(quotient));
            out_buffer.set_target(ct_result_targets[i], F::from_canonical_u64(remainder));
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
            .collect::<IoResult<()>>()?;
        self.ct_result
            .ciphertext_targets()
            .iter()
            .map(|r| dst.write_target(*r))
            .collect::<IoResult<()>>()
    }

    fn deserialize(src: &mut Buffer, common_data: &CommonCircuitData<F, D>) -> IoResult<Self>
    where
        Self: Sized,
    {
        todo!()
    }
}

/// `ArithmeticChip` is contraint builder for arithmetic operations between bfv ciphertexts
struct ArithmeticChip<F: RichField + Extendable<D>, const D: usize, const N: usize, const Q: u64> {
    _marker: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize, const N: usize, const Q: u64>
    ArithmeticChip<F, D, N, Q>
{
    /// Assigns bfv ciphertexts and constrains the correct formulation of ciphertexts
    /// Expects input ciphertext is not in NTT form
    pub fn assign_ciphertexts(
        pw: &mut PartialWitness<F>,
        ct: &Vec<Ciphertext>,
    ) -> Result<Vec<AssignedCiphertext<F, D, N, Q>>, Error> {
        todo!()
    }

    pub fn add_ciphertexts(
        cb: &mut CircuitBuilder<F, D>,
        ct0: AssignedCiphertext<F, D, N, Q>,
        ct1: AssignedCiphertext<F, D, N, Q>,
    ) -> Result<AssignedCiphertext<F, D, N, Q>, Error> {
        let mut ct_result_targets = vec![];
        let quotient = vec![AssignedValue::new(cb); 2 * N];
        let ring_modulus = F::from_canonical_u64(Q);
        let one = F::ONE;
        let neg_one = cb.neg_one();
        for (i, (ct0_target, ct1_target)) in ct0
            .ciphertext_targets()
            .iter()
            .zip(ct1.ciphertext_targets().iter())
            .enumerate()
        {
            let eval_added = cb.add(*ct0_target, *ct1_target);
            let ct_result_eval =
                cb.arithmetic(ring_modulus, one, neg_one, quotient[i].value, eval_added);
            ct_result_targets.push(ct_result_eval);
        }
        let (ct_result_0_targets, ct_result_1_targets) = ct_result_targets.split_at(N);
        let ct_result = AssignedCiphertext::new_from_targets(
            cb,
            ct_result_0_targets.try_into().unwrap(),
            ct_result_1_targets.try_into().unwrap(),
        );
        let arithmetic_ops_generator =
            ArithmeticOpsGenerator::new(cb, ct0, ct1, ct_result, quotient);
        cb.add_simple_generator(arithmetic_ops_generator);
        Ok(ct_result)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::{Error, Ok, Result};
    use plonky2::{
        field::extension::Extendable,
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
        vbfv::{arithmetic_chip::ArithmeticChip, assigned::AssignedCiphertext},
    };

    fn test_add_ciphertexts_helper<const N: usize, const Q: u64>(
        msg_1: Vec<i64>,
        msg_2: Vec<i64>,
        t: i64,
        std_dev: f64,
    ) -> Result<(), Error> {
        // Prepare ciphertexts
        let mut rng = rand::rngs::StdRng::seed_from_u64(19);

        let secret_key = SecretKey::generate(N, &mut rng);
        let public_key = secret_key.public_key_gen(Q as i64, std_dev, &mut rng);

        let plaintext1 = Plaintext::new(msg_1, t);
        let ciphertext1 = plaintext1.encrypt(&public_key, std_dev, &mut rng);
        let decrypted1 = ciphertext1.decrypt(&secret_key);
        assert_eq!(decrypted1.poly(), plaintext1.poly() % (t, N));

        let plaintext2 = Plaintext::new(msg_2, t);
        let ciphertext2 = plaintext2.encrypt(&public_key, std_dev, &mut rng);
        let decrypted2 = ciphertext2.decrypt(&secret_key);
        assert_eq!(decrypted2.poly(), plaintext2.poly() % (t, N));

        let add_ciphertext = ciphertext1.clone() + ciphertext2.clone();

        // constrain adding ciphertexts
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<<C as GenericConfig<D>>::F, D>::new(config);

        let assigned_ct1: AssignedCiphertext<<C as GenericConfig<D>>::F, D, N, Q> =
            AssignedCiphertext::new(&mut builder);
        let assigned_ct2 = AssignedCiphertext::new(&mut builder);
        let assigned_ct_added =
            ArithmeticChip::add_ciphertexts(&mut builder, assigned_ct1, assigned_ct2)?;

        assigned_ct1.register_as_public_input(&mut builder);
        assigned_ct2.register_as_public_input(&mut builder);
        assigned_ct_added.register_as_public_input(&mut builder);

        // assign witnesses
        let mut pw = PartialWitness::new();
        assigned_ct1.assign(&mut pw, ciphertext1)?;
        assigned_ct2.assign(&mut pw, ciphertext2)?;
        assigned_ct_added.assign(&mut pw, add_ciphertext)?;

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;

        data.verify(proof)
    }

    #[test]
    fn test_add_ciphertexts() -> Result<(), Error> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        for t in vec![2, 4, 8, 16, 32].iter() {
            test_add_ciphertexts_helper::<8, 3329>(
                vec![0, 1, 2, 3, 4, 5, 6, 7],
                vec![7, 6, 5, 4, 3, 2, 1, 0],
                *t,
                3.2,
            );
        }
        Ok(())
    }
}
