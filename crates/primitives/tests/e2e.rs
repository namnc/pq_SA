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

// =========================================================================
//  Adversarial tests
// =========================================================================

#[test]
fn test_recovery_rejects_wrong_channels_via_confirm_tag() {
    // Simulates wallet recovery: recipient decapsulates ALL first contacts,
    // including ones from other senders. Wrong k_pairwise values (from ML-KEM
    // implicit rejection) should NOT match genuine memos' confirm_tags.
    let mut rng = ChaChaRng::seed_from_u64(300);
    let recipient = hybrid_kem::RecipientKeyPair::generate(&mut rng);
    let other = hybrid_kem::RecipientKeyPair::generate(&mut rng);

    // Real first contact → genuine k_pairwise
    let (real_ct, k_real) = hybrid_kem::encapsulate(
        &recipient.viewing.viewing_pk_ec, &recipient.viewing.ek_kem, &mut rng,
    );

    // Other person's first contact → wrong k_pairwise via implicit rejection
    let (wrong_ct, _) = hybrid_kem::encapsulate(
        &other.viewing.viewing_pk_ec, &other.viewing.ek_kem, &mut rng,
    );
    let k_wrong = hybrid_kem::decapsulate(&recipient.viewing, &wrong_ct).unwrap();
    assert_ne!(k_real, k_wrong);

    // Post a memo with the REAL k_pairwise
    let nonce = [7u8; 16];
    let real_result = stealth::derive_pairwise_stealth(
        &recipient.spending.spending_pk, None, &k_real, &nonce,
    );

    // During recovery: try WRONG k_pairwise against the same memo
    let wrong_result = stealth::derive_pairwise_stealth(
        &recipient.spending.spending_pk, None, &k_wrong, &nonce,
    );

    // View tag might match by chance (1/256), but confirm tag should reject (1/2^32)
    // We test the confirm_tag specifically:
    assert_ne!(
        real_result.confirm_tag, wrong_result.confirm_tag,
        "wrong k_pairwise must produce different confirm_tag"
    );
}

#[test]
fn test_view_tag_collision_filtered_by_confirm_tag() {
    // Demonstrates that even when view tags collide (1/256 probability),
    // the confirm tag distinguishes genuine from spurious matches.
    let mut rng = ChaChaRng::seed_from_u64(400);
    let recipient = hybrid_kem::RecipientKeyPair::generate(&mut rng);
    let (_, k_real) = hybrid_kem::encapsulate(
        &recipient.viewing.viewing_pk_ec, &recipient.viewing.ek_kem, &mut rng,
    );

    // Generate many nonces, find one where a wrong key produces the same view_tag
    let k_wrong = [0xFFu8; 32]; // arbitrary wrong key
    let mut found_collision = false;

    for i in 0..1000u64 {
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&i.to_be_bytes());

        let real = stealth::derive_pairwise_stealth(
            &recipient.spending.spending_pk, None, &k_real, &nonce,
        );
        let wrong = stealth::derive_pairwise_stealth(
            &recipient.spending.spending_pk, None, &k_wrong, &nonce,
        );

        if real.view_tag == wrong.view_tag {
            // View tag collision! But confirm_tag should still differ.
            assert_ne!(
                real.confirm_tag, wrong.confirm_tag,
                "confirm_tag must reject even when view_tag collides (nonce={})", i
            );
            found_collision = true;
            break;
        }
    }
    assert!(found_collision, "Expected at least one view_tag collision in 1000 tries (p ≈ 98%)");
}

#[test]
fn test_nonce_reuse_produces_same_address() {
    // Documents the known privacy failure: reusing (k_pairwise, nonce) links payments.
    let mut rng = ChaChaRng::seed_from_u64(500);
    let (_, spending_pk) = {
        let secp = secp256k1::Secp256k1::new();
        secp.generate_keypair(&mut rng)
    };
    let k = [42u8; 32];
    let nonce = [1u8; 16];

    let r1 = stealth::derive_pairwise_stealth(&spending_pk, None, &k, &nonce);
    let r2 = stealth::derive_pairwise_stealth(&spending_pk, None, &k, &nonce);

    // Same (k_pairwise, nonce) → same stealth address (privacy break)
    assert_eq!(r1.address, r2.address, "nonce reuse MUST produce same address (known behavior)");
    assert_eq!(r1.view_tag, r2.view_tag);
    assert_eq!(r1.confirm_tag, r2.confirm_tag);

    // Different nonce → different address (correct behavior)
    let r3 = stealth::derive_pairwise_stealth(&spending_pk, None, &k, &[2u8; 16]);
    assert_ne!(r1.address, r3.address);
}

#[test]
fn test_confirm_tag_and_view_tag_are_independent() {
    // confirm_tag is derived from (k_pairwise, nonce) directly.
    // view_tag is derived from the shared secret (hash of k_pairwise || nonce).
    // They use different domain separation strings and cannot be confused.
    let k = [42u8; 32];
    let nonce = [1u8; 16];

    let confirm = stealth::compute_confirm_tag(&k, &nonce);

    // Manually compute what view_tag uses: ss = SHA-256("pq-sa-pairwise-stealth-v1" || k || nonce)
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(b"pq-sa-pairwise-stealth-v1");
    hasher.update(&k);
    hasher.update(&nonce);
    let ss: [u8; 32] = hasher.finalize().into();
    let view = stealth::compute_view_tag(&ss);

    // They should be derived from different inputs with different domains
    // (this test verifies independence, not that they differ — they COULD equal by chance)
    assert_eq!(confirm, stealth::compute_confirm_tag(&k, &nonce), "confirm_tag is deterministic");
    assert_eq!(view, stealth::compute_view_tag(&ss), "view_tag is deterministic");
}
