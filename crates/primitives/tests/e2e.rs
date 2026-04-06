use primitives::*;
use rand_chacha::ChaChaRng;
use rand::{SeedableRng, RngCore};

#[test]
fn test_first_contact_and_stealth_payment() {
    let mut rng = ChaChaRng::seed_from_u64(42);

    let recipient = hybrid_kem::RecipientKeyPair::generate(&mut rng);

    // Sender encapsulates to VIEWING key (not spending)
    let (ct, k_sender) = hybrid_kem::encapsulate(
        &recipient.viewing_pk_ec, &recipient.ek_kem, &mut rng,
    );

    // Recipient decapsulates (uses viewing keys internally, not spending)
    let k_recipient = hybrid_kem::decapsulate(&recipient, &ct).unwrap();
    assert_eq!(k_sender, k_recipient);

    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut nonce);

    // Sender derives stealth address using SPENDING key
    let sender_stealth = stealth::derive_pairwise_stealth(
        &recipient.spending_pk, None, &k_sender, &nonce,
    );

    // Recipient derives same stealth address + private key
    let recv_stealth = stealth::derive_pairwise_stealth(
        &recipient.spending_pk, Some(recipient.spending_sk()), &k_recipient, &nonce,
    );

    assert_eq!(sender_stealth.address, recv_stealth.address);
    assert_eq!(sender_stealth.view_tag, recv_stealth.view_tag);
    assert!(sender_stealth.stealth_sk.is_none());
    assert!(recv_stealth.stealth_sk.is_some());
}

#[test]
fn test_delegation_safety() {
    // Core security property: a scanning server with viewing keys
    // can recover k_pairwise and detect payments, but CANNOT spend.
    let mut rng = ChaChaRng::seed_from_u64(77);

    let recipient = hybrid_kem::RecipientKeyPair::generate(&mut rng);

    // Sender encapsulates
    let (ct, k_sender) = hybrid_kem::encapsulate(
        &recipient.viewing_pk_ec, &recipient.ek_kem, &mut rng,
    );

    // Server decapsulates using viewing keys — succeeds
    let k_server = hybrid_kem::decapsulate(&recipient, &ct).unwrap();
    assert_eq!(k_sender, k_server);

    // Server can derive stealth_pk (detection)
    let nonce = [1u8; 16];
    let server_result = stealth::derive_pairwise_stealth(
        &recipient.spending_pk, None, &k_server, &nonce,
    );
    assert!(server_result.stealth_sk.is_none()); // cannot spend

    // Recipient can derive stealth_sk (spending)
    let owner_result = stealth::derive_pairwise_stealth(
        &recipient.spending_pk, Some(recipient.spending_sk()), &k_server, &nonce,
    );
    assert!(owner_result.stealth_sk.is_some()); // can spend
    assert_eq!(server_result.address, owner_result.address);

    // Verify: viewing keys are DIFFERENT from spending keys
    assert_ne!(recipient.spending_pk_bytes(), recipient.viewing_pk_ec_bytes());
}

#[test]
fn test_wrong_recipient_gets_different_key() {
    let mut rng = ChaChaRng::seed_from_u64(77);

    let recipient1 = hybrid_kem::RecipientKeyPair::generate(&mut rng);
    let recipient2 = hybrid_kem::RecipientKeyPair::generate(&mut rng);

    let (ct, k_sender) = hybrid_kem::encapsulate(
        &recipient1.viewing_pk_ec, &recipient1.ek_kem, &mut rng,
    );

    let k_wrong = hybrid_kem::decapsulate(&recipient2, &ct).unwrap();
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
            &recipient.viewing_pk_ec, &recipient.ek_kem, &mut rng,
        );
        k_pairwises.push(k);
        first_contacts.push(ct);
    }

    // Wallet loss — recover from same seed
    let recovered = hybrid_kem::RecipientKeyPair::from_seed(&seed);

    // All keys match
    assert_eq!(recovered.spending_pk_bytes(), recipient.spending_pk_bytes());
    assert_eq!(recovered.viewing_pk_ec_bytes(), recipient.viewing_pk_ec_bytes());

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

    let (ct, k_pairwise) = hybrid_kem::encapsulate(
        &recipient.viewing_pk_ec, &recipient.ek_kem, &mut rng,
    );
    let k_recv = hybrid_kem::decapsulate(&recipient, &ct).unwrap();
    assert_eq!(k_pairwise, k_recv);

    let mut addresses = Vec::new();
    for _ in 0..10 {
        let mut nonce = [0u8; 16];
        rng.fill_bytes(&mut nonce);

        let sender_result = stealth::derive_pairwise_stealth(
            &recipient.spending_pk, None, &k_pairwise, &nonce,
        );
        let recv_result = stealth::derive_pairwise_stealth(
            &recipient.spending_pk, Some(recipient.spending_sk()), &k_recv, &nonce,
        );

        assert_eq!(sender_result.address, recv_result.address);
        assert!(recv_result.stealth_sk.is_some());
        addresses.push(sender_result.address);
    }

    addresses.sort();
    addresses.dedup();
    assert_eq!(addresses.len(), 10);
}
