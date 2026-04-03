use alloy::{
    primitives::{Address, FixedBytes},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    network::EthereumWallet,
    sol,
};
use clap::Parser;
use eyre::Result;
use primitives::*;
use rand::SeedableRng;
use rand::RngCore;
use rand_chacha::ChaChaRng;

// ---------------------------------------------------------------------------
// Contract ABI + bytecode via alloy sol! macro
// ---------------------------------------------------------------------------
sol! {
    #[sol(rpc, all_derives)]
    NoteRegistry,
    "../../contracts/out/NoteRegistry.sol/NoteRegistry.json"
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
#[derive(Parser)]
#[command(name = "pq-sa-demo", about = "Post-quantum in-band secret distribution demo")]
struct Cli {
    /// RPC endpoint (default: Anvil localhost)
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Private key hex (default: Anvil account 0)
    #[arg(long, default_value = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")]
    private_key: String,

    /// Use existing contract address instead of deploying
    #[arg(long)]
    contract: Option<String>,
}

// ---------------------------------------------------------------------------
// Main demo flow
// ---------------------------------------------------------------------------
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    println!("================================================");
    println!("  PQ In-Band Secret Distribution — Testnet Demo");
    println!("================================================\n");

    // --- Provider setup ---
    let signer: PrivateKeySigner = cli.private_key.parse()?;
    let sender_addr = signer.address();
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(cli.rpc.parse()?);

    println!("[setup] RPC:     {}", cli.rpc);
    println!("[setup] Address: {}\n", sender_addr);

    // Record block number before our transactions for event scanning
    let start_block = provider.get_block_number().await?;

    // --- Deploy or connect to contract ---
    let contract = if let Some(addr_str) = &cli.contract {
        let addr = addr_str.parse()?;
        println!("[contract] Using existing: {}\n", addr);
        NoteRegistry::new(addr, &provider)
    } else {
        println!("[contract] Deploying NoteRegistry (archivalVault=0x0)...");
        // Deploy with address(0) vault — archival disabled for demo
        let zero_addr = Address::ZERO;
        let deployed = NoteRegistry::deploy(&provider, zero_addr).await?;
        println!("[contract] Deployed at: {}\n", deployed.address());
        deployed
    };

    // =====================================================================
    //  RECIPIENT SIDE: Generate keys and register on-chain
    // =====================================================================
    println!("--- RECIPIENT: Key Generation ---");
    let mut rng = ChaChaRng::from_entropy();
    let recipient_keys = hybrid_kem::RecipientKeyPair::generate(&mut rng);

    let pk_ec_bytes = recipient_keys.pk_ec_bytes();
    let ek_kem_bytes = recipient_keys.ek_kem_bytes();

    println!("  pk_ec:  {}... ({} B)", hex::encode(&pk_ec_bytes[..8]), pk_ec_bytes.len());
    println!("  ek_kem: {}... ({} B)", hex::encode(&ek_kem_bytes[..8]), ek_kem_bytes.len());

    println!("\n--- RECIPIENT: Registering keys on-chain ---");
    let reg_receipt = contract
        .registerKeys(pk_ec_bytes.to_vec().into(), ek_kem_bytes.clone().into())
        .send()
        .await?
        .get_receipt()
        .await?;
    println!("  tx:     {}", reg_receipt.transaction_hash);
    println!("  gas:    {}\n", reg_receipt.gas_used);

    // =====================================================================
    //  SENDER SIDE: Look up recipient keys, encapsulate, encrypt, post
    // =====================================================================
    println!("--- SENDER: Reading recipient keys from chain ---");

    // Scan KeyRegistered events to discover recipient keys
    let key_events = contract.KeyRegistered_filter().from_block(start_block).query().await?;
    let (key_event, _) = key_events.last().ok_or_else(|| eyre::eyre!("no KeyRegistered event"))?;

    // Reconstruct recipient public keys from on-chain event data
    let pk_ec_from_chain = hybrid_kem::pk_ec_from_bytes(&key_event.pkEc)
        .map_err(|e| eyre::eyre!("{}", e))?;
    let ek_kem_from_chain = hybrid_kem::ek_kem_from_bytes(&key_event.ekKem)
        .map_err(|e| eyre::eyre!("{}", e))?;

    println!("  Recovered pk_ec:  {}...", hex::encode(&pk_ec_from_chain.serialize()[..8]));
    println!("  Recovered ek_kem: OK ({} B on-chain)", key_event.ekKem.len());

    // --- Encapsulate (hybrid KEM: ECDH + ML-KEM-768) ---
    println!("\n--- SENDER: Hybrid KEM encapsulation ---");
    let (first_ct, k_pairwise) = hybrid_kem::encapsulate(
        &pk_ec_from_chain, &ek_kem_from_chain, &mut rng,
    );
    println!("  k_pairwise: {}...", hex::encode(&k_pairwise[..8]));
    println!("  epk:        {}... ({} B)", hex::encode(&first_ct.epk[..8]), first_ct.epk.len());
    println!("  ct_pq:      {}... ({} B)", hex::encode(&first_ct.ct_pq[..8]), first_ct.ct_pq.len());

    // --- Create and encrypt note ---
    println!("\n--- SENDER: Encrypting note (value=1,000,000) ---");
    let mut nonce_bytes = [0u8; 16];
    rng.fill_bytes(&mut nonce_bytes);
    let null_seed = commitment::nullifier_seed(&k_pairwise, &nonce_bytes);

    let mut blinding = [0u8; 32];
    rng.fill_bytes(&mut blinding);
    let note_plaintext = note::NotePlaintext {
        value: 1_000_000,
        asset_id: [1u8; 32],
        blinding_factor: blinding,
        memo: [0u8; 512],
        nullifier_seed: null_seed,
    };
    let serialized = note_plaintext.serialize();
    let recipient_addr_bytes = [0xABu8; 20]; // placeholder for demo
    let comm = commitment::note_commitment(&serialized, &recipient_addr_bytes);
    let ciphertext = aead::encrypt(&k_pairwise, &nonce_bytes, &serialized)
        .map_err(|e| eyre::eyre!("AEAD encrypt: {}", e))?;

    println!("  plaintext:  {} B", serialized.len());
    println!("  ciphertext: {} B", ciphertext.len());
    println!("  commitment: {}...", hex::encode(&comm[..8]));

    // Pack first-contact payload: epk(33) || ct_pq(1088) || nonce(16) || ciphertext(632)
    let mut payload = Vec::with_capacity(33 + 1088 + 16 + ciphertext.len());
    payload.extend_from_slice(&first_ct.epk);
    payload.extend_from_slice(&first_ct.ct_pq);
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&ciphertext);
    println!("  payload:    {} B total", payload.len());

    // --- Post first contact on-chain ---
    println!("\n--- SENDER: Posting first contact on-chain ---");
    let comm_fixed: FixedBytes<32> = FixedBytes::from(comm);
    let post_receipt = contract
        .postFirstContact(comm_fixed, payload.into())
        .send()
        .await?
        .get_receipt()
        .await?;
    println!("  tx:     {}", post_receipt.transaction_hash);
    println!("  gas:    {}", post_receipt.gas_used);
    println!("  block:  {}", post_receipt.block_number.unwrap_or_default());

    // =====================================================================
    //  SENDER SIDE: Send a second note on established channel
    // =====================================================================
    println!("\n--- SENDER: Sending known-pair note (value=500,000) ---");
    let mut nonce2 = [0u8; 16];
    rng.fill_bytes(&mut nonce2);
    let null_seed2 = commitment::nullifier_seed(&k_pairwise, &nonce2);

    let mut blinding2 = [0u8; 32];
    rng.fill_bytes(&mut blinding2);
    let note2 = note::NotePlaintext {
        value: 500_000,
        asset_id: [1u8; 32],
        blinding_factor: blinding2,
        memo: [0u8; 512],
        nullifier_seed: null_seed2,
    };
    let serialized2 = note2.serialize();
    let comm2 = commitment::note_commitment(&serialized2, &recipient_addr_bytes);
    let ciphertext2 = aead::encrypt(&k_pairwise, &nonce2, &serialized2)
        .map_err(|e| eyre::eyre!("AEAD encrypt: {}", e))?;

    let comm2_fixed: FixedBytes<32> = FixedBytes::from(comm2);
    let nonce2_fixed: FixedBytes<16> = FixedBytes::from(nonce2);

    let post2_receipt = contract
        .postNote(comm2_fixed, nonce2_fixed, ciphertext2.into())
        .send()
        .await?
        .get_receipt()
        .await?;
    println!("  tx:     {}", post2_receipt.transaction_hash);
    println!("  gas:    {}", post2_receipt.gas_used);

    // =====================================================================
    //  RECIPIENT SIDE: Scan chain, decapsulate, decrypt
    // =====================================================================
    println!("\n--- RECIPIENT: Scanning chain for FirstContact events ---");

    let fc_events = contract.FirstContact_filter().from_block(start_block).query().await?;
    println!("  Found {} FirstContact event(s)", fc_events.len());

    for (event, _log) in &fc_events {
        let payload = &event.payload;
        println!("\n  noteId={}, epoch={}", event.noteId, event.epoch);
        println!("  commitment: {}", event.commitment);
        println!("  payload: {} B", payload.len());

        // Unpack: epk(33) || ct_pq(1088) || nonce(16) || ciphertext
        if payload.len() < 33 + 1088 + 16 {
            println!("  ERROR: payload too short");
            continue;
        }
        let epk: [u8; 33] = payload[..33].try_into()?;
        let ct_pq = payload[33..33 + 1088].to_vec();
        let recv_nonce: [u8; 16] = payload[33 + 1088..33 + 1088 + 16].try_into()?;
        let ct_data = &payload[33 + 1088 + 16..];

        // Decapsulate hybrid KEM
        let fc = hybrid_kem::FirstContactCiphertext { epk, ct_pq };
        let k_recv = hybrid_kem::decapsulate(&recipient_keys, &fc)
            .map_err(|e| eyre::eyre!("decapsulate: {}", e))?;
        println!("  k_pairwise: {}...", hex::encode(&k_recv[..8]));

        // Decrypt note
        let decrypted = aead::decrypt(&k_recv, &recv_nonce, ct_data)
            .map_err(|e| eyre::eyre!("AEAD decrypt: {}", e))?;
        let note_out = note::NotePlaintext::deserialize(&decrypted)
            .ok_or_else(|| eyre::eyre!("deserialize failed"))?;

        println!("  ** DECRYPTED: value = {} **", note_out.value);

        // Verify on-chain commitment
        let recomputed = commitment::note_commitment(&decrypted, &recipient_addr_bytes);
        let on_chain_comm: [u8; 32] = event.commitment.0;
        assert_eq!(recomputed, on_chain_comm, "commitment mismatch!");
        println!("  Commitment verified OK");
    }

    // --- Scan NotePosted events (known-pair notes) ---
    println!("\n--- RECIPIENT: Scanning chain for NotePosted events ---");
    let np_events = contract.NotePosted_filter().from_block(start_block).query().await?;
    println!("  Found {} NotePosted event(s)", np_events.len());

    for (event, _log) in &np_events {
        let recv_nonce: [u8; 16] = event.nonce.0;
        let ct_data: &[u8] = &event.ciphertext;

        // Decrypt with established k_pairwise
        let decrypted = aead::decrypt(&k_pairwise, &recv_nonce, ct_data)
            .map_err(|e| eyre::eyre!("AEAD decrypt: {}", e))?;
        let note_out = note::NotePlaintext::deserialize(&decrypted)
            .ok_or_else(|| eyre::eyre!("deserialize failed"))?;

        println!("\n  noteId={}: ** DECRYPTED: value = {} **", event.noteId, note_out.value);

        let recomputed = commitment::note_commitment(&decrypted, &recipient_addr_bytes);
        let on_chain_comm: [u8; 32] = event.commitment.0;
        assert_eq!(recomputed, on_chain_comm, "commitment mismatch!");
        println!("  Commitment verified OK");
    }

    // =====================================================================
    //  RECIPIENT SIDE: Subscription deposit + pay-on-spend
    // =====================================================================
    println!("\n--- RECIPIENT: Depositing subscription balance ---");
    let deposit_amount = alloy::primitives::U256::from(100_000_000_000_000u64); // 0.0001 ETH
    let dep_receipt = contract
        .depositBalance()
        .value(deposit_amount)
        .send()
        .await?
        .get_receipt()
        .await?;
    println!("  tx:      {}", dep_receipt.transaction_hash);
    println!("  deposit: 0.0001 ETH");
    let bal = contract.balances(sender_addr).call().await?;
    println!("  balance: {} wei", bal);

    // Spend the first note (noteId=0) — deducts fee from balance, pays server
    println!("\n--- RECIPIENT: Spending note 0 (pay-on-spend) ---");
    // Generate nullifier from the note's nullifier_seed
    let nullifier = {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(b"nullifier");
        h.update(&k_pairwise);
        h.update(&nonce_bytes);
        FixedBytes::from(<[u8; 32]>::from(h.finalize()))
    };

    let spend_receipt = contract
        .spendNote(0, nullifier)
        .send()
        .await?
        .get_receipt()
        .await?;
    println!("  tx:        {}", spend_receipt.transaction_hash);
    println!("  gas:       {}", spend_receipt.gas_used);
    println!("  nullifier: {}", nullifier);

    // Verify nullifier is recorded (double-spend prevention)
    let is_spent = contract.nullifiers(nullifier).call().await?;
    println!("  spent:     {}", is_spent);

    let bal_after = contract.balances(sender_addr).call().await?;
    println!("  balance:   {} wei (fee deducted: {} wei)", bal_after, bal - bal_after);

    // =====================================================================
    //  Summary
    // =====================================================================
    println!("\n================================================");
    println!("  Demo complete!");
    println!("  Contract:     {}", contract.address());
    println!("  Notes posted: 2 (1 first-contact + 1 known-pair)");
    println!("  All decrypted and commitment-verified");
    println!("  Subscription: deposited, spent note 0 with pay-on-spend");
    println!("  Hybrid KEM: ECDH(secp256k1) + ML-KEM-768");
    println!("  AEAD: ChaCha20-Poly1305");
    println!("================================================");

    Ok(())
}
