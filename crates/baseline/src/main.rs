//! Baseline: Naive ML-KEM-768 note encryption.
//!
//! Every note requires a fresh ML-KEM encapsulation (1088 B ciphertext on-chain).
//! No hybrid ECDH, no pairwise channel reuse, no erasure coding, no HMAC shards.
//! This is the simplest possible "just use ML-KEM" approach, for comparison with PQ-SA.

use alloy::{
    primitives::FixedBytes,
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    network::EthereumWallet,
    sol,
};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use chacha20poly1305::aead::Aead;
use clap::Parser;
use eyre::Result;
use hkdf::Hkdf;
use ml_kem::ml_kem_768::{self, MlKem768};
use ml_kem::{B32, Seed, DecapsulationKey, Decapsulate, KeyExport};
use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use sha2::Sha256;

// ---------------------------------------------------------------------------
// Contract: reuse the same NoteRegistry (every note is a "first contact")
// ---------------------------------------------------------------------------
sol! {
    #[sol(rpc, all_derives)]
    NoteRegistry,
    "../../contracts/out/NoteRegistry.sol/NoteRegistry.json"
}

// ---------------------------------------------------------------------------
// Minimal note structure (same 616 B plaintext as PQ-SA)
// ---------------------------------------------------------------------------
const NOTE_SIZE: usize = 616;

fn make_note(value: u64, rng: &mut ChaChaRng) -> [u8; NOTE_SIZE] {
    let mut buf = [0u8; NOTE_SIZE];
    buf[0..8].copy_from_slice(&value.to_le_bytes());
    buf[8..40].copy_from_slice(&[1u8; 32]); // asset_id
    rng.fill_bytes(&mut buf[40..72]); // blinding
    // memo[72..584] = zeros
    // nullifier_seed[584..616] = zeros (no pairwise key to derive from)
    buf
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(data);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
#[derive(Parser)]
#[command(name = "baseline", about = "Baseline: naive ML-KEM-768 note encryption (no pairwise channels)")]
struct Cli {
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    #[arg(long, default_value = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")]
    private_key: String,

    #[arg(long)]
    contract: Option<String>,

    /// Number of notes to send
    #[arg(long, default_value = "5")]
    notes: usize,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    println!("==========================================================");
    println!("  BASELINE: Naive ML-KEM-768 (no pairwise, no hybrid)");
    println!("==========================================================\n");

    let signer: PrivateKeySigner = cli.private_key.parse()?;
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(cli.rpc.parse()?);

    let start_block = provider.get_block_number().await?;

    let contract = if let Some(addr_str) = &cli.contract {
        let addr = addr_str.parse()?;
        println!("[contract] Using existing: {}\n", addr);
        NoteRegistry::new(addr, &provider)
    } else {
        println!("[contract] Deploying NoteRegistry...");
        let deployed = NoteRegistry::deploy(&provider, alloy::primitives::Address::ZERO).await?;
        println!("[contract] Deployed at: {}\n", deployed.address());
        deployed
    };

    let mut rng = ChaChaRng::from_entropy();

    // =====================================================================
    //  RECIPIENT: Generate ML-KEM-768 keypair (no EC key — ML-KEM only)
    // =====================================================================
    println!("--- RECIPIENT: ML-KEM-768 key generation ---");
    let mut seed_bytes = [0u8; 64];
    rng.fill_bytes(&mut seed_bytes);
    let dk = DecapsulationKey::<MlKem768>::from_seed(
        Seed::try_from(seed_bytes.as_slice()).expect("64 bytes"),
    );
    let ek = dk.encapsulation_key().clone();

    let ek_bytes: Vec<u8> = {
        let arr = ek.to_bytes();
        let s: &[u8] = arr.as_ref();
        s.to_vec()
    };
    println!("  ek_kem: {}... ({} B)", hex::encode(&ek_bytes[..8]), ek_bytes.len());

    // Register with dummy 33-byte pkEc (baseline doesn't use EC, but contract requires it)
    let dummy_pk_ec = vec![0x02u8; 33];
    let reg = contract
        .registerKeys(dummy_pk_ec.into(), ek_bytes.into())
        .send().await?.get_receipt().await?;
    println!("  register gas: {}\n", reg.gas_used);

    // =====================================================================
    //  SENDER: For EACH note, fresh ML-KEM encapsulation
    // =====================================================================
    println!("--- SENDER: Sending {} notes (fresh KEM per note) ---\n", cli.notes);

    let mut total_gas: u128 = 0;
    let mut total_calldata: usize = 0;
    let values: Vec<u64> = (0..cli.notes).map(|i| (i as u64 + 1) * 100_000).collect();

    for (i, &value) in values.iter().enumerate() {
        // Fresh ML-KEM-768 encapsulation for EVERY note
        let mut m_bytes = [0u8; 32];
        rng.fill_bytes(&mut m_bytes);
        let (ct_pq, ss_pq) = ek.encapsulate_deterministic(
            &B32::try_from(m_bytes.as_slice()).expect("32 bytes"),
        );

        // Derive encryption key from ML-KEM shared secret only (no ECDH, no hybrid)
        let ss_ref: &[u8] = ss_pq.as_ref();
        let hk = Hkdf::<Sha256>::new(None, ss_ref);
        let mut key = [0u8; 32];
        hk.expand(b"baseline-mlkem", &mut key).unwrap();

        // Encrypt note
        let plaintext = make_note(value, &mut rng);
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
            .map_err(|_| eyre::eyre!("encrypt failed"))?;

        // Commitment
        let comm = sha256(&plaintext);

        // Pack payload: ct_pq(1088) || nonce(12) || ciphertext(632)
        // Note: baseline uses 12-byte nonce (standard ChaCha20), not 16-byte
        let ct_pq_ref: &[u8] = ct_pq.as_ref();
        let mut payload = Vec::with_capacity(1088 + 12 + ciphertext.len());
        payload.extend_from_slice(ct_pq_ref);
        payload.extend_from_slice(&nonce_bytes);
        payload.extend_from_slice(&ciphertext);

        let comm_fixed: FixedBytes<32> = FixedBytes::from(comm);
        let receipt = contract
            .postFirstContact(comm_fixed, payload.clone().into())
            .send().await?.get_receipt().await?;

        let gas = receipt.gas_used;
        total_gas += gas as u128;
        total_calldata += payload.len();

        println!("  note {}: value={:>9}, payload={} B, gas={}", i, value, payload.len(), gas);
    }

    // =====================================================================
    //  RECIPIENT: Scan and decrypt all notes
    // =====================================================================
    println!("\n--- RECIPIENT: Scanning and decrypting ---");

    let events = contract.FirstContact_filter().from_block(start_block).query().await?;
    println!("  Found {} events", events.len());

    let mut decrypted_count = 0;
    for (event, _) in &events {
        let payload = &event.payload;
        if payload.len() < 1088 + 12 {
            continue;
        }

        let ct_pq_bytes = &payload[..1088];
        let nonce_bytes = &payload[1088..1088 + 12];
        let ct_data = &payload[1088 + 12..];

        // ML-KEM decapsulate
        let ct_pq = match ml_kem_768::Ciphertext::try_from(ct_pq_bytes) {
            Ok(ct) => ct,
            Err(_) => continue,
        };
        let ss_pq = dk.decapsulate(&ct_pq);

        // Derive key
        let ss_ref: &[u8] = ss_pq.as_ref();
        let hk = Hkdf::<Sha256>::new(None, ss_ref);
        let mut key = [0u8; 32];
        hk.expand(b"baseline-mlkem", &mut key).unwrap();

        // Decrypt
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes);
        match cipher.decrypt(nonce, ct_data) {
            Ok(plaintext) => {
                let value = u64::from_le_bytes(plaintext[..8].try_into().unwrap());
                println!("  noteId={}: DECRYPTED value = {}", event.noteId, value);
                decrypted_count += 1;
            }
            Err(_) => {
                println!("  noteId={}: decrypt failed (not for us)", event.noteId);
            }
        }
    }

    // =====================================================================
    //  Comparison summary
    // =====================================================================
    let avg_gas = if cli.notes > 0 { total_gas / cli.notes as u128 } else { 0 };
    let avg_calldata = if cli.notes > 0 { total_calldata / cli.notes } else { 0 };

    println!("\n==========================================================");
    println!("  BASELINE RESULTS ({} notes)", cli.notes);
    println!("  Decrypted:       {}/{}", decrypted_count, cli.notes);
    println!("  Total gas:       {}", total_gas);
    println!("  Avg gas/note:    {}", avg_gas);
    println!("  Avg calldata:    {} B/note", avg_calldata);
    println!("  KEM ciphertext:  1088 B (every note)");
    println!("  No channel reuse, no hybrid ECDH, no erasure coding");
    println!("==========================================================");
    println!();
    println!("  Compare with PQ-SA:");
    println!("    First contact:  ~95K gas, 1769 B calldata");
    println!("    Known-pair:     ~51K gas, ~648 B calldata");
    println!("    After 1st note: {:.0}% less gas, {:.0}% less calldata",
        (1.0 - 51000.0 / avg_gas as f64) * 100.0,
        (1.0 - 648.0 / avg_calldata as f64) * 100.0,
    );
    println!("==========================================================");

    Ok(())
}
