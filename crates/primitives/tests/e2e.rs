use primitives::*;
use rand_chacha::ChaChaRng;
use rand::{SeedableRng, RngCore};

/// Create a test note with given value.
fn make_note(value: u64, rng: &mut impl RngCore) -> note::NotePlaintext {
    let mut blinding = [0u8; 32];
    rng.fill_bytes(&mut blinding);
    note::NotePlaintext {
        value,
        asset_id: [1u8; 32],
        blinding_factor: blinding,
        memo: [0u8; 512],
        nullifier_seed: [0u8; 32], // filled during send
    }
}

#[test]
fn test_first_contact_roundtrip() {
    let mut rng = ChaChaRng::seed_from_u64(42);
    let recipient_addr = [0xABu8; 20];

    // Generate recipient keys
    let recipient = hybrid_kem::RecipientKeyPair::generate(&mut rng);

    // Sender creates first contact
    let (ct, k_sender) = hybrid_kem::encapsulate(
        &recipient.pk_ec, &recipient.ek_kem, &mut rng,
    );

    // Sender creates note with nullifier seed
    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut nonce);
    let null_seed = commitment::nullifier_seed(&k_sender, &nonce);

    let mut note_out = make_note(1_000_000, &mut rng);
    note_out.nullifier_seed = null_seed;

    // Sender encrypts
    let plaintext = note_out.serialize();
    let comm = commitment::note_commitment(&plaintext, &recipient_addr);
    let ciphertext = aead::encrypt(&k_sender, &nonce, &plaintext).unwrap();
    assert_eq!(ciphertext.len(), note::ENCRYPTED_NOTE_SIZE);

    // Recipient decapsulates
    let k_recipient = hybrid_kem::decapsulate(&recipient, &ct).unwrap();
    assert_eq!(k_sender, k_recipient);

    // Recipient decrypts
    let decrypted = aead::decrypt(&k_recipient, &nonce, &ciphertext).unwrap();
    let note_in = note::NotePlaintext::deserialize(&decrypted).unwrap();
    assert_eq!(note_in.value, 1_000_000);
    assert_eq!(note_in.nullifier_seed, null_seed);

    // Verify commitment
    let computed_comm = commitment::note_commitment(&decrypted, &recipient_addr);
    assert_eq!(comm, computed_comm);
}

#[test]
fn test_known_pair_with_erasure_coding() {
    let mut rng = ChaChaRng::seed_from_u64(99);
    let recipient_addr = [0xCDu8; 20];

    // Establish pairwise key
    let recipient = hybrid_kem::RecipientKeyPair::generate(&mut rng);
    let (ct, k_pairwise) = hybrid_kem::encapsulate(
        &recipient.pk_ec, &recipient.ek_kem, &mut rng,
    );
    let k_recipient = hybrid_kem::decapsulate(&recipient, &ct).unwrap();
    assert_eq!(k_pairwise, k_recipient);

    // Sender creates known-pair note
    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut nonce);
    let null_seed = commitment::nullifier_seed(&k_pairwise, &nonce);

    let mut note_out = make_note(500_000, &mut rng);
    note_out.nullifier_seed = null_seed;

    let plaintext = note_out.serialize();
    let comm = commitment::note_commitment(&plaintext, &recipient_addr);
    let ciphertext = aead::encrypt(&k_pairwise, &nonce, &plaintext).unwrap();

    // Erasure encode
    let shards = erasure::encode(&ciphertext, &k_pairwise, &comm, &nonce).unwrap();
    assert_eq!(shards.len(), erasure::M);
    assert_eq!(shards[0].data.len(), (ciphertext.len() + erasure::K - 1) / erasure::K);

    // Simulate: only 4 of 8 shards available (servers 1, 3, 4, 6)
    let mut available: Vec<Option<shard::ShardWithHmac>> = vec![None; erasure::M];
    for i in [1, 3, 4, 6] {
        available[i] = Some(shards[i].clone());
    }

    // Decode
    let recovered_ciphertext = erasure::decode(&available, &k_pairwise).unwrap();
    assert_eq!(recovered_ciphertext, ciphertext);

    // Decrypt
    let decrypted = aead::decrypt(&k_pairwise, &nonce, &recovered_ciphertext).unwrap();
    let note_in = note::NotePlaintext::deserialize(&decrypted).unwrap();
    assert_eq!(note_in.value, 500_000);

    // Verify commitment
    let computed_comm = commitment::note_commitment(&decrypted, &recipient_addr);
    assert_eq!(comm, computed_comm);
}

#[test]
fn test_wrong_recipient_cannot_decrypt() {
    let mut rng = ChaChaRng::seed_from_u64(77);
    let recipient_addr = [0xEFu8; 20];

    let recipient1 = hybrid_kem::RecipientKeyPair::generate(&mut rng);
    let recipient2 = hybrid_kem::RecipientKeyPair::generate(&mut rng);

    // Sender creates note for recipient1
    let (ct, k_sender) = hybrid_kem::encapsulate(
        &recipient1.pk_ec, &recipient1.ek_kem, &mut rng,
    );

    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut nonce);
    let note_out = make_note(999, &mut rng);
    let ciphertext = aead::encrypt(&k_sender, &nonce, &note_out.serialize()).unwrap();

    // Recipient2 tries to decapsulate — gets a different key (ML-KEM implicit rejection)
    let k_wrong = hybrid_kem::decapsulate(&recipient2, &ct).unwrap();
    assert_ne!(k_sender, k_wrong);

    // AEAD decryption fails with wrong key
    let result = aead::decrypt(&k_wrong, &nonce, &ciphertext);
    assert!(result.is_err());
}

#[test]
fn test_wallet_recovery_from_seed() {
    let seed = [42u8; 32];
    let mut rng = ChaChaRng::seed_from_u64(100);
    let recipient_addr = [0x11u8; 20];

    // Generate recipient from seed
    let recipient = hybrid_kem::RecipientKeyPair::from_seed(&seed);

    // Create 3 first contacts from different senders
    let mut channel_ids = Vec::new();
    let mut k_pairwises = Vec::new();
    let mut first_contacts = Vec::new();

    for _ in 0..3 {
        let (ct, k) = hybrid_kem::encapsulate(
            &recipient.pk_ec, &recipient.ek_kem, &mut rng,
        );
        let chan_id = channel::channel_id(&ct.epk, &ct.ct_pq);
        channel_ids.push(chan_id);
        k_pairwises.push(k);
        first_contacts.push(ct);
    }

    // Simulate wallet loss — re-derive from same seed
    let recovered_recipient = hybrid_kem::RecipientKeyPair::from_seed(&seed);

    // Verify all first contacts can be decapsulated
    for (i, ct) in first_contacts.iter().enumerate() {
        let k_recovered = hybrid_kem::decapsulate(&recovered_recipient, ct).unwrap();
        assert_eq!(k_recovered, k_pairwises[i], "channel {} key mismatch", i);
    }
}

#[test]
fn test_multiple_senders_multiple_notes() {
    let mut rng = ChaChaRng::seed_from_u64(200);
    let recipient_addr = [0x22u8; 20];
    let recipient = hybrid_kem::RecipientKeyPair::generate(&mut rng);

    // 3 senders, each sends 5 notes
    let mut all_k_pairwise = Vec::new();
    let mut all_notes: Vec<(u64, [u8; 16], [u8; 32], Vec<shard::ShardWithHmac>)> = Vec::new();

    for sender_idx in 0..3u64 {
        // First contact
        let (ct, k) = hybrid_kem::encapsulate(
            &recipient.pk_ec, &recipient.ek_kem, &mut rng,
        );
        let k_recv = hybrid_kem::decapsulate(&recipient, &ct).unwrap();
        assert_eq!(k, k_recv);
        all_k_pairwise.push(k);

        // 5 known-pair notes
        for note_idx in 0..5u64 {
            let value = (sender_idx + 1) * 1000 + note_idx * 100;
            let mut nonce = [0u8; 16];
            rng.fill_bytes(&mut nonce);

            let null_seed = commitment::nullifier_seed(&k, &nonce);
            let mut note_out = make_note(value, &mut rng);
            note_out.nullifier_seed = null_seed;

            let plaintext = note_out.serialize();
            let comm = commitment::note_commitment(&plaintext, &recipient_addr);
            let ciphertext = aead::encrypt(&k, &nonce, &plaintext).unwrap();
            let shards = erasure::encode(&ciphertext, &k, &comm, &nonce).unwrap();

            all_notes.push((value, nonce, comm, shards));
        }
    }

    // Recipient recovers all 15 notes using k_pairwise from each sender
    let mut recovered_values = Vec::new();
    for (expected_value, nonce, _comm, shards) in &all_notes {
        // Try each k_pairwise — only the correct one will produce valid AEAD
        for k in &all_k_pairwise {
            // Use shards 0,1,2,3
            let mut available: Vec<Option<shard::ShardWithHmac>> = vec![None; erasure::M];
            for i in 0..erasure::K {
                available[i] = Some(shards[i].clone());
            }

            if let Ok(ciphertext) = erasure::decode(&available, k) {
                if let Ok(plaintext) = aead::decrypt(k, nonce, &ciphertext) {
                    if let Some(note) = note::NotePlaintext::deserialize(&plaintext) {
                        recovered_values.push(note.value);
                        break;
                    }
                }
            }
        }
    }

    assert_eq!(recovered_values.len(), 15);
    // Verify all expected values are present
    for (expected_value, _, _, _) in &all_notes {
        assert!(recovered_values.contains(expected_value),
            "missing value {}", expected_value);
    }
}
