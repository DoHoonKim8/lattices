#[cfg(test)]
mod tests {
    use crate::bfv::keys::SecretKey;
    use crate::bfv::plaintext::Plaintext;
    use rand::SeedableRng;

    fn encrypt_decrypt_helper(msg: Vec<i64>, t: i64, q: i64, std_dev: f64) {
        let degree = msg.len();
        let mut rng = rand::rngs::StdRng::seed_from_u64(18);

        let secret_key = SecretKey::generate(degree, &mut rng);
        let public_key = secret_key.public_key_gen(q, std_dev, &mut rng);

        let plaintext = Plaintext::new(msg, t);
        let ciphertext = plaintext.encrypt(&public_key, std_dev, &mut rng);

        let decrypted = ciphertext.decrypt(&secret_key);

        assert_eq!(decrypted.poly(), plaintext.poly() % (t, degree));
    }

    #[test]
    fn encrypt_decrypt() {
        for t in vec![2, 4, 8, 16, 32].iter() {
            encrypt_decrypt_helper(vec![1, 0], *t, 65536, 3.2);
            encrypt_decrypt_helper(vec![3, 2, 1, 0], *t, 65536, 3.2);
            encrypt_decrypt_helper(vec![0, 1, 2, 3, 4, 5, 6, 7], *t, 65536, 3.2);
        }
    }

    fn encrypt_add_sub_decrypt_helper(
        msg_1: Vec<i64>,
        msg_2: Vec<i64>,
        t: i64,
        q: i64,
        std_dev: f64,
    ) {
        let q = 3329;
        let degree = msg_1.len();
        let mut rng = rand::rngs::StdRng::seed_from_u64(19);

        let secret_key = SecretKey::generate(degree, &mut rng);
        let public_key = secret_key.public_key_gen(q, std_dev, &mut rng);

        let plaintext_1 = Plaintext::new(msg_1, t);
        let ciphertext_1 = plaintext_1.encrypt(&public_key, std_dev, &mut rng);
        let decrypted_1 = ciphertext_1.decrypt(&secret_key);
        assert_eq!(decrypted_1.poly(), plaintext_1.poly() % (t, degree));

        let plaintext_2 = Plaintext::new(msg_2, t);
        let ciphertext_2 = plaintext_2.encrypt(&public_key, std_dev, &mut rng);
        let decrypted_2 = ciphertext_2.decrypt(&secret_key);
        assert_eq!(decrypted_2.poly(), plaintext_2.poly() % (t, degree));

        let add_ciphertext = ciphertext_1.clone() + ciphertext_2.clone();
        let decrypted_add = add_ciphertext.decrypt(&secret_key);
        let expected_add = (plaintext_1.poly() + plaintext_2.poly()) % (t, degree);
        assert_eq!(decrypted_add.poly(), expected_add);

        let sub_ciphertext = ciphertext_1.clone() - ciphertext_2;
        let decrypted_sub = sub_ciphertext.decrypt(&secret_key);
        let expected_sub = (plaintext_1.poly() - plaintext_2.poly()) % (t, degree);
        assert_eq!(decrypted_sub.poly(), expected_sub);

        let neg_ciphertext = -ciphertext_1;
        let decrypted_neg = neg_ciphertext.decrypt(&secret_key);
        let expected_neg = -plaintext_1.poly() % (t, degree);
        assert_eq!(decrypted_neg.poly(), expected_neg);
    }

    #[test]
    fn encrypt_add_sub_decrypt() {
        for t in vec![2, 4, 8, 16, 32].iter() {
            encrypt_add_sub_decrypt_helper(vec![0, 6], vec![7, 2], *t, 65536, 3.2);
            encrypt_add_sub_decrypt_helper(vec![3, 2, 1, 0], vec![1, 2, 3, 4], *t, 65536, 3.2);
            encrypt_add_sub_decrypt_helper(
                vec![0, 1, 2, 3, 4, 5, 6, 7],
                vec![7, 6, 5, 4, 3, 2, 1, 0],
                *t,
                65536,
                3.2,
            );
        }
    }

    fn basic_mul_helper(msg_1: Vec<i64>, msg_2: Vec<i64>, t: i64, q: i64, std_dev: f64) {
        let degree = msg_1.len();
        let mut rng = rand::rngs::StdRng::seed_from_u64(20);

        let secret_key = SecretKey::generate(degree, &mut rng);
        let public_key = secret_key.public_key_gen(q, std_dev, &mut rng);

        let plaintext_1 = Plaintext::new(msg_1, t);
        let ciphertext_1 = plaintext_1.encrypt(&public_key, std_dev, &mut rng);
        let plaintext_2 = Plaintext::new(msg_2, t);
        let ciphertext_2 = plaintext_2.encrypt(&public_key, std_dev, &mut rng);

        // Multiply without relinearizing
        let (c_0, c_1, c_2) = ciphertext_1.clone().basic_mul(ciphertext_2.clone());

        // Decrypt non-relinearized multilication output
        let s = secret_key.poly;
        let delta_inv = t as f64 / q as f64;
        let raw = c_0.clone() + c_1.clone() * s.clone() + c_2.clone() * s.clone() * s.clone();
        let decrypted_mul = (raw * delta_inv) % (t, degree);

        assert_eq!(
            decrypted_mul,
            (plaintext_1.poly() * plaintext_2.poly()) % (t, degree)
        );
    }

    // Test that ciphertext multiplication without relinearization encrypt/decrypts correctly
    #[test]
    fn basic_mul_test() {
        for t in vec![2, 4, 8, 16, 32].iter() {
            basic_mul_helper(vec![0, 6], vec![7, 2], *t, 65536, 1.0);
            basic_mul_helper(vec![3, 2, 1, 0], vec![1, 2, 3, 4], *t, 65536, 1.0);
        }
    }

    fn relin_1_mul_helper(
        msg_1: Vec<i64>,
        msg_2: Vec<i64>,
        t: i64,
        q: i64,
        std_dev: f64,
        base: i64,
    ) {
        let degree = msg_1.len();
        let mut rng = rand::rngs::StdRng::seed_from_u64(21);

        let secret_key = SecretKey::generate(degree, &mut rng);
        let public_key = secret_key.public_key_gen(q, std_dev, &mut rng);

        let plaintext_1 = Plaintext::new(msg_1, t);
        let ciphertext_1 = plaintext_1.encrypt(&public_key, std_dev, &mut rng);
        let plaintext_2 = Plaintext::new(msg_2, t);
        let ciphertext_2 = plaintext_2.encrypt(&public_key, std_dev, &mut rng);

        // Homomorphic multiplication with relinearization
        let rlk_1 = secret_key.relin_key_gen_1(q, std_dev, &mut rng, base);
        let mul_ciphertext = ciphertext_1.clone() * (ciphertext_2.clone(), &rlk_1);
        let decrypted_mul = mul_ciphertext.decrypt(&secret_key);
        assert_eq!(
            decrypted_mul.poly(),
            (plaintext_1.poly() * plaintext_2.poly()) % (t, degree)
        );
    }

    // Test that ciphertext multiplication using relinearization Version #1 encrypt/decrypts correctly
    #[test]
    fn relin_1_mul_test() {
        let q = 65536;
        // Choosing T = ceil(sqrt(q)) to minimize relinearisation time and space.
        // This can be toggled to be smaller so that the error introduced is smaller.
        // With this base choice, we can tolerate error to std_dev=1.5.
        let base_sqrt = (q as f64).sqrt().ceil() as i64;
        let std_dev_sqrt = 1.5;

        for t in vec![4, 8, 16, 32].iter() {
            relin_1_mul_helper(vec![0, 1], vec![0, 0], *t, q, std_dev_sqrt, base_sqrt);
            relin_1_mul_helper(
                vec![3, 2, 1, 0],
                vec![1, 2, 3, 4],
                *t,
                q,
                std_dev_sqrt,
                base_sqrt,
            );
            relin_1_mul_helper(
                vec![0, 1, 2, 3, 0, 1, 2, 3],
                vec![3, 2, 1, 0, 3, 2, 1, 0],
                *t,
                q,
                std_dev_sqrt,
                base_sqrt,
            );
        }

        // Choosing T = log_2(q) to decrease error at the cost of relinearisation time and space.
        // With this base choice, we can tolerate error to std_dev=2.9.
        let base_log = (q as f64).log2() as i64;
        let std_dev_log = 2.9;

        for t in vec![4, 8, 16, 32].iter() {
            relin_1_mul_helper(vec![0, 1], vec![0, 0], *t, q, std_dev_log, base_log);
            relin_1_mul_helper(
                vec![3, 2, 1, 0],
                vec![1, 2, 3, 4],
                *t,
                q,
                std_dev_log,
                base_log,
            );
            relin_1_mul_helper(
                vec![0, 1, 2, 3, 0, 1, 2, 3],
                vec![3, 2, 1, 0, 3, 2, 1, 0],
                *t,
                q,
                std_dev_log,
                base_log,
            );
        }
    }

    fn relin_2_mul_helper(msg_1: Vec<i64>, msg_2: Vec<i64>, t: i64, q: i64, std_dev: f64, p: i64) {
        let degree = msg_1.len();
        let mut rng = rand::rngs::StdRng::seed_from_u64(22);

        let secret_key = SecretKey::generate(degree, &mut rng);
        let public_key = secret_key.public_key_gen(q, std_dev, &mut rng);

        let plaintext_1 = Plaintext::new(msg_1, t);
        let ciphertext_1 = plaintext_1.encrypt(&public_key, std_dev, &mut rng);
        let plaintext_2 = Plaintext::new(msg_2, t);
        let ciphertext_2 = plaintext_2.encrypt(&public_key, std_dev, &mut rng);

        // Homomorphic multiplication with relinearization
        let rlk_2 = secret_key.relin_key_gen_2(q, std_dev, &mut rng, p);
        let mul_ciphertext = ciphertext_1.clone() * (ciphertext_2.clone(), &rlk_2);
        let decrypted_mul = mul_ciphertext.decrypt(&secret_key);
        assert_eq!(
            decrypted_mul.poly(),
            (plaintext_1.poly() * plaintext_2.poly()) % (t, degree)
        );
    }

    // Test that ciphertext multiplication using relinearization Version #2 encrypt/decrypts correctly
    #[test]
    fn relin_2_mul_test() {
        let q = 65536;
        // Technically p should be >= q^3 for security (see paper discussion on Relinearization Version 2),
        // but setting p = q^3 results in an overflow when taking p * q so we will test with a smaller p.
        let p = 2_i64.pow(13) * q;
        let std_dev = 2.0;

        for t in vec![4, 8, 16, 32].iter() {
            relin_2_mul_helper(vec![0, 1], vec![0, 0], *t, q, std_dev, p);
            relin_2_mul_helper(vec![3, 2, 1, 0], vec![1, 2, 3, 4], *t, q, std_dev, p);
            relin_2_mul_helper(
                vec![0, 1, 2, 3, 0, 1, 2, 3],
                vec![3, 2, 1, 0, 3, 2, 1, 0],
                *t,
                q,
                std_dev,
                p,
            );
        }
    }

    #[test]
    fn end_to_end_test() {
        for _ in 0..1000 {
            let q = 65536;
            let t = 16;
            let std_dev = 3.2;
            let degree = 4;
            let rlk_base = (q as f64).log2() as i64;
            let mut rng = rand::rngs::StdRng::seed_from_u64(23);

            let secret_key = SecretKey::generate(degree, &mut rng);
            let public_key = secret_key.public_key_gen(q, std_dev, &mut rng);
            let rlk_1 = secret_key.relin_key_gen_1(q, std_dev, &mut rng, rlk_base);

            let pt_1 = Plaintext::rand(degree, t, &mut rng);
            let pt_2 = Plaintext::rand(degree, t, &mut rng);
            let pt_3 = Plaintext::rand(degree, t, &mut rng);
            let pt_4 = Plaintext::rand(degree, t, &mut rng);

            let ct_1 = pt_1.encrypt(&public_key, std_dev, &mut rng);
            let ct_2 = pt_2.encrypt(&public_key, std_dev, &mut rng);
            let ct_3 = pt_3.encrypt(&public_key, std_dev, &mut rng);
            let ct_4 = pt_4.encrypt(&public_key, std_dev, &mut rng);

            let expr_ct = ct_1 * (ct_2, &rlk_1) + ct_3 * (ct_4, &rlk_1);
            let expr_pt = expr_ct.decrypt(&secret_key);

            let expected_pt = (pt_1.poly() * pt_2.poly() + pt_3.poly() * pt_4.poly()) % (t, degree);
            assert_eq!(expr_pt.poly(), expected_pt);
        }
    }
}
