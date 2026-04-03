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
#[command(name = "pq-sa-demo", about = "Post-quantum stealth address demo")]
struct Cli {
    /// RPC endpoint (default: Anvil localhost)
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Sender private key (default: Anvil account 0)
    #[arg(long, default_value = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")]
    sender_key: String,

    /// Recipient private key (default: Anvil account 1)
    #[arg(long, default_value = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")]
    recipient_key: String,

    /// Use existing contract address instead of deploying
    #[arg(long)]
    contract: Option<String>,
}

// ---------------------------------------------------------------------------
// Main demo flow — uses SEPARATE sender and recipient wallets
// ---------------------------------------------------------------------------
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    println!("================================================");
    println!("  PQ Stealth Address — Testnet Demo");
    println!("================================================\n");

    // --- Two separate signers ---
    let sender_signer: PrivateKeySigner = cli.sender_key.parse()?;
    let recipient_signer: PrivateKeySigner = cli.recipient_key.parse()?;
    let sender_addr = sender_signer.address();
    let recipient_addr = recipient_signer.address();

    // Provider with sender wallet (for posting notes)
    let sender_wallet = EthereumWallet::from(sender_signer);
    let sender_provider = ProviderBuilder::new()
        .wallet(sender_wallet)
        .connect_http(cli.rpc.parse()?);

    // Provider with recipient wallet (for registration, deposit, spend)
    let recipient_wallet = EthereumWallet::from(recipient_signer);
    let recipient_provider = ProviderBuilder::new()
        .wallet(recipient_wallet)
        .connect_http(cli.rpc.parse()?);

    println!("[setup] RPC:       {}", cli.rpc);
    println!("[setup] Sender:    {}", sender_addr);
    println!("[setup] Recipient: {}\n", recipient_addr);

    let start_block = sender_provider.get_block_number().await?;

    // --- Deploy or connect (sender deploys) ---
    let sender_contract = if let Some(addr_str) = &cli.contract {
        let addr = addr_str.parse()?;
        println!("[contract] Using existing: {}\n", addr);
        NoteRegistry::new(addr, &sender_provider)
    } else {
        println!("[contract] Deploying NoteRegistry...");
        let deployed = NoteRegistry::deploy(&sender_provider, Address::ZERO).await?;
        println!("[contract] Deployed at: {}\n", deployed.address());
        deployed
    };

    // Recipient's view of the same contract
    let recipient_contract = NoteRegistry::new(*sender_contract.address(), &recipient_provider);

    // =====================================================================
    //  RECIPIENT: Generate keys and register on-chain
    // =====================================================================
    println!("--- RECIPIENT: Key Generation ---");
    let mut rng = ChaChaRng::from_entropy();
    let recipient_keys = hybrid_kem::RecipientKeyPair::generate(&mut rng);

    let pk_ec_bytes = recipient_keys.pk_ec_bytes();
    let ek_kem_bytes = recipient_keys.ek_kem_bytes();

    println!("  pk_ec:  {}... ({} B)", hex::encode(&pk_ec_bytes[..8]), pk_ec_bytes.len());
    println!("  ek_kem: {}... ({} B)", hex::encode(&ek_kem_bytes[..8]), ek_kem_bytes.len());

    println!("\n--- RECIPIENT: Registering keys on-chain ---");
    let reg_receipt = recipient_contract
        .registerKeys(pk_ec_bytes.to_vec().into(), ek_kem_bytes.clone().into())
        .send()
        .await?
        .get_receipt()
        .await?;
    println!("  tx:     {}", reg_receipt.transaction_hash);
    println!("  gas:    {}\n", reg_receipt.gas_used);

    // =====================================================================
    //  SENDER: Look up recipient keys, encapsulate, encrypt, post
    // =====================================================================
    println!("--- SENDER: Reading recipient keys from chain ---");

    let key_events = sender_contract.KeyRegistered_filter().from_block(start_block).query().await?;
    let (key_event, _) = key_events.last().ok_or_else(|| eyre::eyre!("no KeyRegistered event"))?;

    let pk_ec_from_chain = hybrid_kem::pk_ec_from_bytes(&key_event.pkEc)
        .map_err(|e| eyre::eyre!("{}", e))?;
    let ek_kem_from_chain = hybrid_kem::ek_kem_from_bytes(&key_event.ekKem)
        .map_err(|e| eyre::eyre!("{}", e))?;

    println!("  Recovered pk_ec:  {}...", hex::encode(&pk_ec_from_chain.serialize()[..8]));
    println!("  Recovered ek_kem: OK ({} B on-chain)", key_event.ekKem.len());

    // --- Hybrid KEM encapsulation ---
    println!("\n--- SENDER: Hybrid KEM encapsulation ---");
    let (first_ct, k_pairwise) = hybrid_kem::encapsulate(
        &pk_ec_from_chain, &ek_kem_from_chain, &mut rng,
    );
    println!("  k_pairwise: {}...", hex::encode(&k_pairwise[..8]));

    // --- Create and encrypt note ---
    // Use REAL recipient address (from their Ethereum address) for commitment binding
    let recipient_addr_bytes: [u8; 20] = recipient_addr.0 .0;

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
    let comm = commitment::note_commitment(&serialized, &recipient_addr_bytes);
    let ciphertext = aead::encrypt(&k_pairwise, &nonce_bytes, &serialized)
        .map_err(|e| eyre::eyre!("AEAD encrypt: {}", e))?;

    println!("  plaintext:  {} B", serialized.len());
    println!("  ciphertext: {} B", ciphertext.len());
    println!("  commitment: {}...", hex::encode(&comm[..8]));

    let mut payload = Vec::with_capacity(33 + 1088 + 16 + ciphertext.len());
    payload.extend_from_slice(&first_ct.epk);
    payload.extend_from_slice(&first_ct.ct_pq);
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&ciphertext);

    // --- Post first contact (SENDER's transaction) ---
    println!("\n--- SENDER: Posting first contact on-chain ---");
    let comm_fixed: FixedBytes<32> = FixedBytes::from(comm);
    let post_receipt = sender_contract
        .postFirstContact(comm_fixed, payload.into())
        .send()
        .await?
        .get_receipt()
        .await?;
    println!("  tx:     {}", post_receipt.transaction_hash);
    println!("  gas:    {}", post_receipt.gas_used);

    // --- Second note (known-pair, SENDER's transaction) ---
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

    let post2_receipt = sender_contract
        .postNote(comm2_fixed, nonce2_fixed, ciphertext2.into())
        .send()
        .await?
        .get_receipt()
        .await?;
    println!("  tx:     {}", post2_receipt.transaction_hash);
    println!("  gas:    {}", post2_receipt.gas_used);

    // =====================================================================
    //  RECIPIENT: Scan chain, decapsulate, decrypt
    // =====================================================================
    println!("\n--- RECIPIENT: Scanning chain for FirstContact events ---");

    let fc_events = recipient_contract.FirstContact_filter().from_block(start_block).query().await?;
    println!("  Found {} FirstContact event(s)", fc_events.len());

    let mut recovered_k_pairwise = [0u8; 32];

    for (event, _log) in &fc_events {
        let payload = &event.payload;
        if payload.len() < 33 + 1088 + 16 { continue; }

        let epk: [u8; 33] = payload[..33].try_into()?;
        let ct_pq = payload[33..33 + 1088].to_vec();
        let recv_nonce: [u8; 16] = payload[33 + 1088..33 + 1088 + 16].try_into()?;
        let ct_data = &payload[33 + 1088 + 16..];

        let fc = hybrid_kem::FirstContactCiphertext { epk, ct_pq };
        let k_recv = hybrid_kem::decapsulate(&recipient_keys, &fc)
            .map_err(|e| eyre::eyre!("decapsulate: {}", e))?;
        recovered_k_pairwise = k_recv;
        println!("  k_pairwise: {}...", hex::encode(&k_recv[..8]));

        let decrypted = aead::decrypt(&k_recv, &recv_nonce, ct_data)
            .map_err(|e| eyre::eyre!("AEAD decrypt: {}", e))?;
        let note_out = note::NotePlaintext::deserialize(&decrypted)
            .ok_or_else(|| eyre::eyre!("deserialize failed"))?;
        println!("  ** DECRYPTED: value = {} **", note_out.value);

        let recomputed = commitment::note_commitment(&decrypted, &recipient_addr_bytes);
        assert_eq!(recomputed, event.commitment.0, "commitment mismatch!");
        println!("  Commitment verified OK");
    }

    // --- Known-pair notes ---
    println!("\n--- RECIPIENT: Scanning chain for NotePosted events ---");
    let np_events = recipient_contract.NotePosted_filter().from_block(start_block).query().await?;
    println!("  Found {} NotePosted event(s)", np_events.len());

    for (event, _log) in &np_events {
        let recv_nonce: [u8; 16] = event.nonce.0;
        let ct_data: &[u8] = &event.ciphertext;

        let decrypted = aead::decrypt(&recovered_k_pairwise, &recv_nonce, ct_data)
            .map_err(|e| eyre::eyre!("AEAD decrypt: {}", e))?;
        let note_out = note::NotePlaintext::deserialize(&decrypted)
            .ok_or_else(|| eyre::eyre!("deserialize failed"))?;
        println!("  noteId={}: ** DECRYPTED: value = {} **", event.noteId, note_out.value);

        let recomputed = commitment::note_commitment(&decrypted, &recipient_addr_bytes);
        assert_eq!(recomputed, event.commitment.0, "commitment mismatch!");
        println!("  Commitment verified OK");
    }

    // =====================================================================
    //  RECIPIENT: Deposit subscription + spend note using canonical nullifier
    // =====================================================================
    println!("\n--- RECIPIENT: Depositing subscription balance ---");
    let deposit_amount = alloy::primitives::U256::from(100_000_000_000_000u64);
    let dep_receipt = recipient_contract
        .depositBalance()
        .value(deposit_amount)
        .send()
        .await?
        .get_receipt()
        .await?;
    println!("  tx:      {}", dep_receipt.transaction_hash);
    println!("  deposit: 0.0001 ETH");

    let bal = recipient_contract.balances(recipient_addr).call().await?;
    println!("  balance: {} wei", bal);

    // Spend note 0 using CANONICAL nullifier derivation (same as nullifier_seed in the note)
    println!("\n--- RECIPIENT: Spending note 0 (canonical nullifier) ---");
    let nullifier = FixedBytes::from(
        commitment::nullifier_seed(&recovered_k_pairwise, &nonce_bytes)
    );

    let spend_receipt = recipient_contract
        .spendNote(0, nullifier)
        .send()
        .await?
        .get_receipt()
        .await?;
    println!("  tx:        {}", spend_receipt.transaction_hash);
    println!("  gas:       {}", spend_receipt.gas_used);
    println!("  nullifier: {}", nullifier);

    let is_spent = recipient_contract.spent(0).call().await?;
    println!("  spent:     {}", is_spent);

    let bal_after = recipient_contract.balances(recipient_addr).call().await?;
    println!("  balance:   {} wei (fee deducted: {} wei)", bal_after, bal - bal_after);

    // =====================================================================
    //  Summary
    // =====================================================================
    println!("\n================================================");
    println!("  Demo complete!");
    println!("  Contract:     {}", sender_contract.address());
    println!("  Sender:       {} (posted notes)", sender_addr);
    println!("  Recipient:    {} (registered, decrypted, spent)", recipient_addr);
    println!("  Notes posted: 2 (1 first-contact + 1 known-pair)");
    println!("  All decrypted and commitment-verified");
    println!("  Spend: note 0 nullified with canonical nullifier_seed");
    println!("  Hybrid KEM: ECDH(secp256k1) + ML-KEM-768");
    println!("  AEAD: ChaCha20-Poly1305");
    println!("================================================");

    Ok(())
}
