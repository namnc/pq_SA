//! Classical baseline: ECDH-only stealth address style note encryption.
//!
//! Every note uses fresh ECDH (33 B ephemeral key). No ML-KEM, no pairwise channels.
//! This is the ERC-5564 equivalent with an encrypted note payload.
//! Shows the cost of the classical approach that PQ replaces.

use alloy::{
    primitives::{Address, FixedBytes},
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
use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use sha2::Sha256;

sol! {
    #[sol(rpc, all_derives)]
    NoteRegistry,
    "../../contracts/out/NoteRegistry.sol/NoteRegistry.json"
}

const NOTE_SIZE: usize = 616;

fn make_note(value: u64, rng: &mut ChaChaRng) -> [u8; NOTE_SIZE] {
    let mut buf = [0u8; NOTE_SIZE];
    buf[0..8].copy_from_slice(&value.to_le_bytes());
    buf[8..40].copy_from_slice(&[1u8; 32]);
    rng.fill_bytes(&mut buf[40..72]);
    buf
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(data);
    h.finalize().into()
}

#[derive(Parser)]
#[command(name = "classical", about = "Classical ECDH-only note encryption (ERC-5564 equivalent)")]
struct Cli {
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    #[arg(long, default_value = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")]
    private_key: String,

    #[arg(long)]
    contract: Option<String>,

    #[arg(long, default_value = "5")]
    notes: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    println!("==========================================================");
    println!("  CLASSICAL: ECDH-only note encryption (no PQ)");
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
        let deployed = NoteRegistry::deploy(&provider, Address::ZERO).await?;
        println!("[contract] Deployed at: {}\n", deployed.address());
        deployed
    };

    let mut rng = ChaChaRng::from_entropy();

    // =====================================================================
    //  RECIPIENT: Generate secp256k1 keypair only (no ML-KEM)
    // =====================================================================
    println!("--- RECIPIENT: Classical key generation ---");
    let secp = secp256k1::Secp256k1::new();
    let (recipient_sk, recipient_pk) = secp.generate_keypair(&mut rng);

    let pk_bytes = recipient_pk.serialize(); // 33 B compressed
    println!("  pk:     {}... ({} B)", hex::encode(&pk_bytes[..8]), pk_bytes.len());

    // Register with dummy ekKem (contract requires 1184 B — fill with zeros)
    let dummy_ek = vec![0u8; 1184];
    let reg = contract
        .registerKeys(pk_bytes.to_vec().into(), dummy_ek.into())
        .send().await?.get_receipt().await?;
    println!("  register gas: {}\n", reg.gas_used);

    // =====================================================================
    //  SENDER: For EACH note, fresh ECDH (like ERC-5564 stealth addresses)
    // =====================================================================
    println!("--- SENDER: Sending {} notes (fresh ECDH per note) ---\n", cli.notes);

    let mut total_gas: u128 = 0;
    let mut total_calldata: usize = 0;
    let values: Vec<u64> = (0..cli.notes).map(|i| (i as u64 + 1) * 100_000).collect();

    for (i, &value) in values.iter().enumerate() {
        // Fresh ECDH for every note (classical approach)
        let (esk, epk) = secp.generate_keypair(&mut rng);
        let ecdh_point = secp256k1::ecdh::shared_secret_point(&recipient_pk, &esk);
        let ss_ec = &ecdh_point[..32];

        // Derive key via HKDF (same as PQ-SA but without ML-KEM component)
        let hk = Hkdf::<Sha256>::new(None, ss_ec);
        let mut key = [0u8; 32];
        hk.expand(b"classical-ecdh", &mut key).unwrap();

        // Encrypt note
        let plaintext = make_note(value, &mut rng);
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
            .map_err(|_| eyre::eyre!("encrypt failed"))?;

        let comm = sha256(&plaintext);

        // Pack payload: epk(33) + nonce(12) + ciphertext(632) = 677 B
        // This is the classical equivalent — no ML-KEM ciphertext
        let epk_bytes = epk.serialize();
        let mut payload = Vec::with_capacity(33 + 12 + ciphertext.len());
        payload.extend_from_slice(&epk_bytes);
        payload.extend_from_slice(&nonce_bytes);
        payload.extend_from_slice(&ciphertext);

        let comm_fixed: FixedBytes<32> = FixedBytes::from(comm);
        let receipt = contract
            .postFirstContact(comm_fixed, payload.clone().into())
            .send().await?.get_receipt().await?;

        let gas = receipt.gas_used;
        total_gas += gas as u128;
        total_calldata += payload.len() + 32; // + commitment

        println!("  note {}: value={:>9}, payload={} B, gas={}", i, value, payload.len(), gas);
    }

    // =====================================================================
    //  RECIPIENT: Scan and decrypt
    // =====================================================================
    println!("\n--- RECIPIENT: Scanning and decrypting ---");

    let events = contract.FirstContact_filter().from_block(start_block).query().await?;
    println!("  Found {} events", events.len());

    let mut decrypted_count = 0;
    for (event, _) in &events {
        let payload = &event.payload;
        if payload.len() < 33 + 12 {
            continue;
        }

        let epk_bytes = &payload[..33];
        let nonce_bytes = &payload[33..33 + 12];
        let ct_data = &payload[33 + 12..];

        // ECDH with ephemeral key
        let epk = match secp256k1::PublicKey::from_slice(epk_bytes) {
            Ok(k) => k,
            Err(_) => continue,
        };
        let ecdh_point = secp256k1::ecdh::shared_secret_point(&epk, &recipient_sk);
        let ss_ec = &ecdh_point[..32];

        let hk = Hkdf::<Sha256>::new(None, ss_ec);
        let mut key = [0u8; 32];
        hk.expand(b"classical-ecdh", &mut key).unwrap();

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
    //  Summary
    // =====================================================================
    let avg_gas = if cli.notes > 0 { total_gas / cli.notes as u128 } else { 0 };
    let avg_calldata = if cli.notes > 0 { total_calldata / cli.notes } else { 0 };

    println!("\n==========================================================");
    println!("  CLASSICAL RESULTS ({} notes)", cli.notes);
    println!("  Decrypted:       {}/{}", decrypted_count, cli.notes);
    println!("  Total gas:       {}", total_gas);
    println!("  Avg gas/note:    {}", avg_gas);
    println!("  Avg calldata:    {} B/note", avg_calldata);
    println!("  Ephemeral key:   33 B (every note)");
    println!("  ML-KEM ct:       0 B (no PQ protection)");
    println!("  ECDH-only, no PQ security, no pairwise channels");
    println!("==========================================================");
    println!();
    println!("  Compare with PQ-SA:");
    println!("    First contact:  ~117K gas, 1769 B calldata (PQ+classical hybrid)");
    println!("    Known-pair:     ~74K gas, 680 B calldata");
    println!("    Classical:      {}K gas, {} B calldata (ECDH only, no PQ)", avg_gas/1000, avg_calldata);
    println!("    PQ tax (1st):   +{} B calldata (+{:.0}%)",
        1769 - avg_calldata,
        (1769.0 / avg_calldata as f64 - 1.0) * 100.0);
    println!("    PQ tax (2nd+):  +{} B calldata (+{:.0}%)",
        680_i64 - avg_calldata as i64,
        (680.0 / avg_calldata as f64 - 1.0) * 100.0);
    println!("==========================================================");

    Ok(())
}
