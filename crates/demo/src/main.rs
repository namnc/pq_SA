use alloy::{
    primitives::{Address, FixedBytes, U256},
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

sol! {
    #[sol(rpc, all_derives)]
    MemoRegistry,
    "../../contracts/out/MemoRegistry.sol/MemoRegistry.json"
}

#[derive(Parser)]
#[command(name = "pq-sa-demo", about = "Post-quantum stealth address demo")]
struct Cli {
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Sender private key (Anvil account 0)
    #[arg(long, default_value = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")]
    sender_key: String,

    /// Recipient private key (Anvil account 1)
    #[arg(long, default_value = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")]
    recipient_key: String,

    #[arg(long)]
    contract: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    println!("================================================");
    println!("  PQ Stealth Address — Demo");
    println!("================================================\n");

    let sender_signer: PrivateKeySigner = cli.sender_key.parse()?;
    let recipient_signer: PrivateKeySigner = cli.recipient_key.parse()?;
    let sender_addr = sender_signer.address();
    let recipient_addr = recipient_signer.address();

    let sender_provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(sender_signer))
        .connect_http(cli.rpc.parse()?);

    let recipient_provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(recipient_signer))
        .connect_http(cli.rpc.parse()?);

    println!("[setup] Sender:    {}", sender_addr);
    println!("[setup] Recipient: {}\n", recipient_addr);

    let start_block = sender_provider.get_block_number().await?;

    // =====================================================================
    //  Deploy MemoRegistry
    // =====================================================================
    let contract = if let Some(addr_str) = &cli.contract {
        let addr = addr_str.parse()?;
        println!("[contract] Using existing: {}\n", addr);
        MemoRegistry::new(addr, &sender_provider)
    } else {
        println!("[contract] Deploying MemoRegistry...");
        let deployed = MemoRegistry::deploy(&sender_provider).await?;
        println!("[contract] Deployed at: {}\n", deployed.address());
        deployed
    };

    // =====================================================================
    //  RECIPIENT: Generate keys, register on-chain
    // =====================================================================
    println!("--- RECIPIENT: Key Generation ---");
    let mut rng = ChaChaRng::from_entropy();
    let recipient_keys = hybrid_kem::RecipientKeyPair::generate(&mut rng);

    let spending_pk_bytes = recipient_keys.spending_pk_bytes();
    let viewing_pk_ec_bytes = recipient_keys.viewing_pk_ec_bytes();
    let ek_kem_bytes = recipient_keys.ek_kem_bytes();

    println!("  spending_pk:    {}... ({} B)", hex::encode(&spending_pk_bytes[..8]), spending_pk_bytes.len());
    println!("  viewing_pk_ec:  {}... ({} B)", hex::encode(&viewing_pk_ec_bytes[..8]), viewing_pk_ec_bytes.len());
    println!("  viewing_ek:     {}... ({} B)", hex::encode(&ek_kem_bytes[..8]), ek_kem_bytes.len());

    let recipient_contract = MemoRegistry::new(*contract.address(), &recipient_provider);
    let reg = recipient_contract
        .registerKeys(
            spending_pk_bytes.to_vec().into(),
            viewing_pk_ec_bytes.to_vec().into(),
            ek_kem_bytes.clone().into(),
        )
        .send().await?.get_receipt().await?;
    println!("  register gas: {}\n", reg.gas_used);

    // =====================================================================
    //  SENDER: First contact (hybrid KEM → k_pairwise)
    // =====================================================================
    println!("--- SENDER: First Contact (Hybrid KEM) ---");

    // Demo: takes last event. Production client must filter by intended recipient address.
    let key_events = contract.KeyRegistered_filter().from_block(start_block).query().await?;
    let (key_event, _) = key_events.last().ok_or_else(|| eyre::eyre!("no KeyRegistered"))?;
    let spending_pk = hybrid_kem::pk_ec_from_bytes(&key_event.spendingPk).map_err(|e| eyre::eyre!("{}", e))?;
    let viewing_pk_ec = hybrid_kem::pk_ec_from_bytes(&key_event.viewingPkEc).map_err(|e| eyre::eyre!("{}", e))?;
    let ek_kem = hybrid_kem::ek_kem_from_bytes(&key_event.viewingEk).map_err(|e| eyre::eyre!("{}", e))?;

    // Encapsulate to VIEWING key (not spending key)
    let (first_ct, k_pairwise) = hybrid_kem::encapsulate(&viewing_pk_ec, &ek_kem, &mut rng);
    println!("  k_pairwise: {}...", hex::encode(&k_pairwise[..8]));

    // Pack and post first contact
    let mut payload = Vec::new();
    payload.extend_from_slice(&first_ct.epk);
    payload.extend_from_slice(&first_ct.ct_pq);
    let fc_receipt = contract
        .postFirstContact(payload.into())
        .send().await?.get_receipt().await?;
    println!("  first contact gas: {} ({} B payload)\n", fc_receipt.gas_used, 33 + 1088);

    // =====================================================================
    //  SENDER: Payment via stealth address
    // =====================================================================
    println!("--- SENDER: Payment via Stealth Address ---");

    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut nonce);

    // Stealth address uses SPENDING key (not viewing key)
    let sender_stealth = stealth::derive_pairwise_stealth(
        &spending_pk, None, &k_pairwise, &nonce,
    );
    let stealth_addr = Address::from_slice(&sender_stealth.address);
    println!("  stealth address: {}", stealth_addr);
    println!("  view tag: 0x{:02x}", sender_stealth.view_tag);

    // Post memo on-chain
    let nonce_fixed = FixedBytes::from(nonce);
    let memo_receipt = contract
        .postMemo(nonce_fixed, sender_stealth.view_tag)
        .send().await?.get_receipt().await?;
    println!("  memo gas: {}", memo_receipt.gas_used);

    // Send ETH to stealth address
    let amount = U256::from(1_000_000_000_000_000u64); // 0.001 ETH
    let tx = alloy::rpc::types::TransactionRequest::default()
        .to(stealth_addr)
        .value(amount);
    let eth_receipt = sender_provider.send_transaction(tx).await?.get_receipt().await?;
    println!("  ETH transfer gas: {}", eth_receipt.gas_used);
    println!("  sent: 0.001 ETH to {}\n", stealth_addr);

    // =====================================================================
    //  RECIPIENT: Scan memos, derive stealth address, verify balance
    // =====================================================================
    println!("--- RECIPIENT: Scanning Memos ---");

    // Demo: takes last event. Production client must try all FirstContact events
    // and filter by successful decapsulation (ML-KEM implicit rejection handles wrong recipient).
    let fc_events = contract.FirstContact_filter().from_block(start_block).query().await?;
    let (fc_event, _) = fc_events.last().ok_or_else(|| eyre::eyre!("no FirstContact"))?;
    let fc_payload = &fc_event.payload;
    let epk: [u8; 33] = fc_payload[..33].try_into()?;
    let ct_pq = fc_payload[33..33 + 1088].to_vec();
    let fc = hybrid_kem::FirstContactCiphertext { epk, ct_pq };
    let k_recv = hybrid_kem::decapsulate(&recipient_keys, &fc)
        .map_err(|e| eyre::eyre!("{}", e))?;
    println!("  k_pairwise: {}...", hex::encode(&k_recv[..8]));
    assert_eq!(k_recv, k_pairwise);

    // Scan memo events
    let memo_events = contract.Memo_filter().from_block(start_block).query().await?;
    println!("  Found {} memo(s)", memo_events.len());

    for (event, _) in &memo_events {
        let recv_nonce: [u8; 16] = event.nonce.0;

        // Derive shared secret and check view tag FIRST (filters 99.6% of non-matches)
        let recv_stealth = stealth::derive_pairwise_stealth(
            &recipient_keys.spending_pk,
            Some(recipient_keys.spending_sk()),
            &k_recv,
            &recv_nonce,
        );

        if recv_stealth.view_tag != event.viewTag {
            // View tag mismatch — not our memo (99.6% of non-matches caught here)
            continue;
        }

        let recv_addr = Address::from_slice(&recv_stealth.address);
        println!("  derived stealth: {} (view tag matched)", recv_addr);

        let balance = recipient_provider.get_balance(recv_addr).await?;
        println!("  balance: {} wei", balance);

        if balance > U256::ZERO {
            println!("  ** PAYMENT FOUND: {} wei at {} **", balance, recv_addr);

            let stealth_sk = recv_stealth.stealth_sk.unwrap();
            let secp = secp256k1::Secp256k1::new();
            let stealth_pk = secp256k1::PublicKey::from_secret_key(&secp, &stealth_sk);
            println!("  stealth_pk: {}...", hex::encode(&stealth_pk.serialize()[..8]));
            println!("  recipient CAN sign from this address (has stealth_sk)");
        }
    }

    println!("\n================================================");
    println!("  Demo complete!");
    println!("  Contract:  {}", contract.address());
    println!("  Sender:    {} (posted first contact + memo + ETH)", sender_addr);
    println!("  Recipient: {} (decapsulated, derived stealth addr, found payment)", recipient_addr);
    println!("  Stealth:   {} (0.001 ETH)", stealth_addr);
    println!("  Model: Pairwise channel + stealth address");
    println!("  Auth: Ethereum-native (no nullifiers, no ZK)");
    println!("  PQ: ECDH + ML-KEM-768 hybrid KEM");
    println!("  Delegation: viewing keys safe to share (spending key stays local)");
    println!("================================================");

    Ok(())
}
