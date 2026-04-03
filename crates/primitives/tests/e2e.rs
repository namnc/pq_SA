use primitives::*;
use rand_chacha::ChaChaRng;
use rand::{SeedableRng, RngCore};

#[test]
fn test_first_contact_and_stealth_payment() {
    let mut rng = ChaChaRng::seed_from_u64(42);

    // Recipient generates keys
    let recipient = hybrid_kem::RecipientKeyPair::generate(&mut rng);

    // Sender: first contact (hybrid KEM → k_pairwise)
    let (ct, k_sender) = hybrid_kem::encapsulate(
        &recipient.pk_ec, &recipient.ek_kem, &mut rng,
    );

    // Recipient: decapsulate to get same k_pairwise
    let k_recipient = hybrid_kem::decapsulate(&recipient, &ct).unwrap();
    assert_eq!(k_sender, k_recipient);

    // Sender: derive stealth address from pairwise key + nonce
    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut nonce);
    let sender_stealth = stealth::derive_pairwise_stealth(
        &recipient.pk_ec, None, &k_sender, &nonce,
    );

    // Recipient: derive same stealth address + private key
    let recv_stealth = stealth::derive_pairwise_stealth(
        &recipient.pk_ec, Some(&recipient.sk_ec), &k_recipient, &nonce,
    );

    // Addresses match
    assert_eq!(sender_stealth.address, recv_stealth.address);
    assert_eq!(sender_stealth.view_tag, recv_stealth.view_tag);

    // Recipient has stealth_sk, sender does not
    assert!(sender_stealth.stealth_sk.is_none());
    assert!(recv_stealth.stealth_sk.is_some());
}

#[test]
fn test_wrong_recipient_gets_different_key() {
    let mut rng = ChaChaRng::seed_from_u64(77);

    let recipient1 = hybrid_kem::RecipientKeyPair::generate(&mut rng);
    let recipient2 = hybrid_kem::RecipientKeyPair::generate(&mut rng);

    // Sender encapsulates to recipient1
    let (ct, k_sender) = hybrid_kem::encapsulate(
        &recipient1.pk_ec, &recipient1.ek_kem, &mut rng,
    );

    // Recipient2 tries to decapsulate — gets different key (ML-KEM implicit rejection)
    let k_wrong = hybrid_kem::decapsulate(&recipient2, &ct).unwrap();
    assert_ne!(k_sender, k_wrong);

    // Same nonce → different stealth addresses
    let nonce = [1u8; 16];
    let addr1 = stealth::derive_pairwise_stealth(
        &recipient1.pk_ec, None, &k_sender, &nonce,
    );
    let addr2 = stealth::derive_pairwise_stealth(
        &recipient2.pk_ec, None, &k_wrong, &nonce,
    );
    assert_ne!(addr1.address, addr2.address);
}

#[test]
fn test_wallet_recovery_from_seed() {
    let seed = [42u8; 32];
    let mut rng = ChaChaRng::seed_from_u64(100);

    let recipient = hybrid_kem::RecipientKeyPair::from_seed(&seed);

    // 3 senders establish pairwise keys
    let mut k_pairwises = Vec::new();
    let mut first_contacts = Vec::new();
    for _ in 0..3 {
        let (ct, k) = hybrid_kem::encapsulate(
            &recipient.pk_ec, &recipient.ek_kem, &mut rng,
        );
        k_pairwises.push(k);
        first_contacts.push(ct);
    }

    // Wallet loss — recover from seed
    let recovered = hybrid_kem::RecipientKeyPair::from_seed(&seed);

    // All pairwise keys recoverable
    for (i, ct) in first_contacts.iter().enumerate() {
        let k_recovered = hybrid_kem::decapsulate(&recovered, ct).unwrap();
        assert_eq!(k_recovered, k_pairwises[i]);
    }
}

#[test]
fn test_multiple_payments_same_pair() {
    let mut rng = ChaChaRng::seed_from_u64(200);
    let recipient = hybrid_kem::RecipientKeyPair::generate(&mut rng);

    // First contact
    let (ct, k_pairwise) = hybrid_kem::encapsulate(
        &recipient.pk_ec, &recipient.ek_kem, &mut rng,
    );
    let k_recv = hybrid_kem::decapsulate(&recipient, &ct).unwrap();
    assert_eq!(k_pairwise, k_recv);

    // 10 payments with different nonces → all different stealth addresses
    let mut addresses = Vec::new();
    for _ in 0..10 {
        let mut nonce = [0u8; 16];
        rng.fill_bytes(&mut nonce);

        let sender_result = stealth::derive_pairwise_stealth(
            &recipient.pk_ec, None, &k_pairwise, &nonce,
        );
        let recv_result = stealth::derive_pairwise_stealth(
            &recipient.pk_ec, Some(&recipient.sk_ec), &k_recv, &nonce,
        );

        assert_eq!(sender_result.address, recv_result.address);
        assert!(recv_result.stealth_sk.is_some());
        addresses.push(sender_result.address);
    }

    // All 10 addresses unique
    addresses.sort();
    addresses.dedup();
    assert_eq!(addresses.len(), 10);
}

#[test]
fn test_viewing_key_cannot_spend() {
    let mut rng = ChaChaRng::seed_from_u64(300);
    let recipient = hybrid_kem::RecipientKeyPair::generate(&mut rng);

    let (ct, k_pairwise) = hybrid_kem::encapsulate(
        &recipient.pk_ec, &recipient.ek_kem, &mut rng,
    );
    let k_recv = hybrid_kem::decapsulate(&recipient, &ct).unwrap();

    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut nonce);

    // Server with viewing key can detect (compute stealth_pk + address)
    let server_result = stealth::derive_pairwise_stealth(
        &recipient.pk_ec, None, &k_recv, &nonce,
    );
    assert!(server_result.stealth_sk.is_none()); // cannot spend

    // Recipient with spending key can spend
    let owner_result = stealth::derive_pairwise_stealth(
        &recipient.pk_ec, Some(&recipient.sk_ec), &k_recv, &nonce,
    );
    assert!(owner_result.stealth_sk.is_some()); // can spend
    assert_eq!(server_result.address, owner_result.address); // same address
}
