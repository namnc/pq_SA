use primitives::*;
use rand_chacha::ChaChaRng;
use rand::{SeedableRng, RngCore};

#[test]
fn test_first_contact_and_stealth_payment() {
    let mut rng = ChaChaRng::seed_from_u64(42);
    let recipient = hybrid_kem::RecipientKeyPair::generate(&mut rng);

    let (ct, k_sender) = hybrid_kem::encapsulate(
        &recipient.viewing.viewing_pk_ec, &recipient.viewing.ek_kem, &mut rng,
    );
    let k_recipient = hybrid_kem::decapsulate(&recipient.viewing, &ct).unwrap();
    assert_eq!(k_sender, k_recipient);

    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut nonce);

    let sender_stealth = stealth::derive_pairwise_stealth(
        &recipient.spending.spending_pk, None, &k_sender, &nonce,
    );
    let recv_stealth = stealth::derive_pairwise_stealth(
        &recipient.spending.spending_pk, Some(recipient.spending.spending_sk()), &k_recipient, &nonce,
    );

    assert_eq!(sender_stealth.address, recv_stealth.address);
    assert!(sender_stealth.stealth_sk.is_none());
    assert!(recv_stealth.stealth_sk.is_some());
}

#[test]
fn test_delegation_safety() {
    let mut rng = ChaChaRng::seed_from_u64(77);
    let recipient = hybrid_kem::RecipientKeyPair::generate(&mut rng);

    // Server receives only ViewingKeys — type system prevents access to spending_sk
    let viewing = &recipient.viewing;
    let (ct, k_sender) = hybrid_kem::encapsulate(
        &viewing.viewing_pk_ec, &viewing.ek_kem, &mut rng,
    );
    let k_server = hybrid_kem::decapsulate(viewing, &ct).unwrap();
    assert_eq!(k_sender, k_server);

    let nonce = [1u8; 16];
    let server_result = stealth::derive_pairwise_stealth(
        &recipient.spending.spending_pk, None, &k_server, &nonce,
    );
    assert!(server_result.stealth_sk.is_none());

    let owner_result = stealth::derive_pairwise_stealth(
        &recipient.spending.spending_pk, Some(recipient.spending.spending_sk()), &k_server, &nonce,
    );
    assert!(owner_result.stealth_sk.is_some());
    assert_eq!(server_result.address, owner_result.address);
    assert_ne!(recipient.spending.spending_pk_bytes(), recipient.viewing.viewing_pk_ec_bytes());
}

#[test]
fn test_wrong_recipient_gets_different_key() {
    let mut rng = ChaChaRng::seed_from_u64(77);
    let r1 = hybrid_kem::RecipientKeyPair::generate(&mut rng);
    let r2 = hybrid_kem::RecipientKeyPair::generate(&mut rng);

    let (ct, k_sender) = hybrid_kem::encapsulate(
        &r1.viewing.viewing_pk_ec, &r1.viewing.ek_kem, &mut rng,
    );
    // ML-KEM implicit rejection: always returns a key, even for wrong recipient
    let k_wrong = hybrid_kem::decapsulate(&r2.viewing, &ct).unwrap();
    assert_ne!(k_sender, k_wrong);
}

#[test]
fn test_wallet_recovery_from_seed() {
    let seed = [42u8; 32];
    let mut rng = ChaChaRng::seed_from_u64(100);
    let recipient = hybrid_kem::RecipientKeyPair::from_seed(&seed);

    let mut k_pairwises = Vec::new();
    let mut first_contacts = Vec::new();
    for _ in 0..3 {
        let (ct, k) = hybrid_kem::encapsulate(
            &recipient.viewing.viewing_pk_ec, &recipient.viewing.ek_kem, &mut rng,
        );
        k_pairwises.push(k);
        first_contacts.push(ct);
    }

    let recovered = hybrid_kem::RecipientKeyPair::from_seed(&seed);
    assert_eq!(recovered.spending.spending_pk_bytes(), recipient.spending.spending_pk_bytes());
    assert_eq!(recovered.viewing.viewing_pk_ec_bytes(), recipient.viewing.viewing_pk_ec_bytes());

    for (i, ct) in first_contacts.iter().enumerate() {
        let k_recovered = hybrid_kem::decapsulate(&recovered.viewing, ct).unwrap();
        assert_eq!(k_recovered, k_pairwises[i]);
    }
}

#[test]
fn test_multiple_payments_same_pair() {
    let mut rng = ChaChaRng::seed_from_u64(200);
    let recipient = hybrid_kem::RecipientKeyPair::generate(&mut rng);

    let (ct, k_pairwise) = hybrid_kem::encapsulate(
        &recipient.viewing.viewing_pk_ec, &recipient.viewing.ek_kem, &mut rng,
    );
    let k_recv = hybrid_kem::decapsulate(&recipient.viewing, &ct).unwrap();
    assert_eq!(k_pairwise, k_recv);

    let mut addresses = Vec::new();
    for _ in 0..10 {
        let mut nonce = [0u8; 16];
        rng.fill_bytes(&mut nonce);
        let sender_result = stealth::derive_pairwise_stealth(
            &recipient.spending.spending_pk, None, &k_pairwise, &nonce,
        );
        let recv_result = stealth::derive_pairwise_stealth(
            &recipient.spending.spending_pk, Some(recipient.spending.spending_sk()), &k_recv, &nonce,
        );
        assert_eq!(sender_result.address, recv_result.address);
        assert!(recv_result.stealth_sk.is_some());
        addresses.push(sender_result.address);
    }
    addresses.sort();
    addresses.dedup();
    assert_eq!(addresses.len(), 10);
}
