use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

/// Encrypt note plaintext using ChaCha20-Poly1305.
/// Uses first 12 bytes of the 16-byte nonce (ChaCha20 requires 96-bit nonce).
/// The full 16-byte nonce goes on calldata for C3 compatibility.
pub fn encrypt(
    key: &[u8; 32],
    nonce_16: &[u8; 16],
    plaintext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| "invalid key length")?;
    let nonce = Nonce::from_slice(&nonce_16[..12]);
    cipher.encrypt(nonce, plaintext)
        .map_err(|_| "encryption failed")
}

/// Decrypt ciphertext using ChaCha20-Poly1305.
/// Returns plaintext or error if AEAD tag verification fails.
pub fn decrypt(
    key: &[u8; 32],
    nonce_16: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| "invalid key length")?;
    let nonce = Nonce::from_slice(&nonce_16[..12]);
    cipher.decrypt(nonce, ciphertext)
        .map_err(|_| "decryption failed (wrong key or corrupted)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let nonce = [1u8; 16];
        let plaintext = b"hello world, this is a test message for AEAD encryption";

        let ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        assert_ne!(&ciphertext[..], plaintext);
        assert_eq!(ciphertext.len(), plaintext.len() + 16); // +16 for Poly1305 tag

        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key = [42u8; 32];
        let wrong_key = [43u8; 32];
        let nonce = [1u8; 16];
        let plaintext = b"secret";

        let ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        let result = decrypt(&wrong_key, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_nonce_fails() {
        let key = [42u8; 32];
        let nonce = [1u8; 16];
        let wrong_nonce = [2u8; 16];
        let plaintext = b"secret";

        let ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        let result = decrypt(&key, &wrong_nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [42u8; 32];
        let nonce = [1u8; 16];
        let plaintext = b"secret";

        let mut ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        ciphertext[0] ^= 0xFF; // flip a byte
        let result = decrypt(&key, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_note_sized_payload() {
        let key = [42u8; 32];
        let nonce = [1u8; 16];
        let plaintext = vec![0xAB; crate::note::NOTE_PLAINTEXT_SIZE];

        let ciphertext = encrypt(&key, &nonce, &plaintext).unwrap();
        assert_eq!(ciphertext.len(), crate::note::ENCRYPTED_NOTE_SIZE);

        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
