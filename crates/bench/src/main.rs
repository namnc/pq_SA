//! Benchmark: Classical ERC-5564 vs Direct ML-KEM vs Pairwise Channel
//!
//! Compares CPU time and gas cost for stealth address payments across three models.
//! Gas is computed analytically from calldata sizes (16 gas/nonzero byte).

use hkdf::Hkdf;
use ml_kem::ml_kem_768::MlKem768;
use ml_kem::{B32, Seed, DecapsulationKey, Decapsulate};
use primitives::*;
use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use serde::Serialize;
use sha2::Sha256;
use std::time::Instant;

const PAYMENT_COUNTS: &[usize] = &[1, 2, 5, 10, 20, 50];
const WARMUP: usize = 3;
const ITERS: usize = 10;

// Gas model (Ethereum mainnet)
const GAS_ETH_TRANSFER: u64 = 21_000;
const GAS_CALLDATA_PER_BYTE: u64 = 16; // nonzero byte
const GAS_EVENT_BASE: u64 = 375; // LOG0
const GAS_EVENT_TOPIC: u64 = 375; // per indexed topic
const GAS_TX_BASE: u64 = 21_000;
const GAS_SSTORE_COLD: u64 = 22_100; // nextMemoId increment (cold)
const GAS_SSTORE_WARM: u64 = 5_000; // nextMemoId increment (warm, same tx)
const GAS_FUNC_OVERHEAD: u64 = 2_600; // function dispatch + memory

/// Estimate gas for an announcement transaction.
fn estimate_announcement_gas(calldata_bytes: usize) -> u64 {
    GAS_TX_BASE
        + GAS_FUNC_OVERHEAD
        + GAS_CALLDATA_PER_BYTE * calldata_bytes as u64
        + GAS_EVENT_BASE + 2 * GAS_EVENT_TOPIC // 2 indexed topics
        + GAS_SSTORE_COLD // nextMemoId++
}

#[derive(Serialize, Clone)]
struct BenchResult {
    model: String,
    payments: usize,
    setup_calldata: usize,
    per_payment_calldata: usize,
    total_calldata: usize,
    setup_gas: u64,
    per_payment_gas: u64,
    total_gas: u64,
    avg_send_us: u64,
    avg_recv_us: u64,
}

fn main() {
    let mut rng = ChaChaRng::seed_from_u64(42);

    println!("================================================================");
    println!("  Gas Comparison: Classical vs Direct ML-KEM vs Pairwise Channel");
    println!("================================================================\n");

    let mut results: Vec<BenchResult> = Vec::new();

    for &n in PAYMENT_COUNTS {
        results.push(bench_classical(n, &mut rng));
        results.push(bench_direct_mlkem(n, &mut rng));
        results.push(bench_pairwise(n, &mut rng));
    }

    // Print comparison table
    println!("\n{:<14} {:>4} {:>10} {:>10} {:>10} {:>10} {:>10}",
        "Model", "N", "Setup(B)", "Per-pay(B)", "Total(B)", "Total gas", "Gas/pay");
    println!("{}", "-".repeat(80));

    for r in &results {
        println!("{:<14} {:>4} {:>10} {:>10} {:>10} {:>10} {:>10}",
            r.model, r.payments, r.setup_calldata, r.per_payment_calldata,
            r.total_calldata, r.total_gas, r.per_payment_gas + GAS_ETH_TRANSFER);
    }

    // Print per-payment gas comparison (including ETH transfer)
    println!("\n--- Per-Payment Gas (announcement + 21K ETH transfer) ---\n");
    println!("{:<14} {:>4} {:>12} {:>12} {:>12}",
        "", "N", "Classical", "Direct KEM", "Pairwise");
    println!("{}", "-".repeat(60));

    for &n in PAYMENT_COUNTS {
        let cl = results.iter().find(|r| r.model == "Classical" && r.payments == n).unwrap();
        let dk = results.iter().find(|r| r.model == "Direct KEM" && r.payments == n).unwrap();
        let pw = results.iter().find(|r| r.model == "Pairwise" && r.payments == n).unwrap();

        let cl_total = cl.total_gas / n as u64 + GAS_ETH_TRANSFER;
        let dk_total = dk.total_gas / n as u64 + GAS_ETH_TRANSFER;
        let pw_total = pw.total_gas / n as u64 + GAS_ETH_TRANSFER;

        println!("{:<14} {:>4} {:>12} {:>12} {:>12}", "", n, cl_total, dk_total, pw_total);
    }

    // CPU timing
    println!("\n--- CPU Time (microseconds) ---\n");
    println!("{:<14} {:>4} {:>10} {:>10}",
        "Model", "N", "Send(us)", "Recv(us)");
    println!("{}", "-".repeat(45));
    for r in &results {
        println!("{:<14} {:>4} {:>10} {:>10}",
            r.model, r.payments, r.avg_send_us, r.avg_recv_us);
    }

    // =====================================================================
    //  Scanning benchmark: how fast can a recipient scan N memos?
    // =====================================================================
    println!("\n--- Scanning Benchmark ---\n");
    bench_scanning(&mut rng);

    // Save JSON + SVG
    let json = serde_json::to_string_pretty(&results).unwrap();
    std::fs::write("bench_results.json", &json).unwrap();
    println!("\nResults saved to bench_results.json");

    generate_svg(&results);
}

// =========================================================================
//  Classical ERC-5564: fresh ECDH per payment, 33 B ephemeral key + 1 B view tag
// =========================================================================
fn bench_classical(num_payments: usize, rng: &mut ChaChaRng) -> BenchResult {
    let secp = secp256k1::Secp256k1::new();
    let (spending_sk, spending_pk) = secp.generate_keypair(rng);
    let (viewing_sk, viewing_pk) = secp.generate_keypair(rng);

    // Warmup
    for _ in 0..WARMUP {
        classical_send_recv(num_payments, &spending_pk, &viewing_sk, &viewing_pk, rng);
    }

    let mut send_us = Vec::new();
    let mut recv_us = Vec::new();
    for _ in 0..ITERS {
        let (s, r) = classical_send_recv(num_payments, &spending_pk, &viewing_sk, &viewing_pk, rng);
        send_us.push(s);
        recv_us.push(r);
    }

    let calldata_per = 34; // 33 B epk + 1 B view tag
    let ann_gas = estimate_announcement_gas(calldata_per);

    BenchResult {
        model: "Classical".into(),
        payments: num_payments,
        setup_calldata: 0,
        per_payment_calldata: calldata_per,
        total_calldata: calldata_per * num_payments,
        setup_gas: 0,
        per_payment_gas: ann_gas,
        total_gas: ann_gas * num_payments as u64,
        avg_send_us: send_us.iter().sum::<u64>() / ITERS as u64,
        avg_recv_us: recv_us.iter().sum::<u64>() / ITERS as u64,
    }
}

fn classical_send_recv(
    n: usize,
    spending_pk: &secp256k1::PublicKey,
    viewing_sk: &secp256k1::SecretKey,
    viewing_pk: &secp256k1::PublicKey,
    rng: &mut ChaChaRng,
) -> (u64, u64) {
    let secp = secp256k1::Secp256k1::new();
    let mut epks = Vec::with_capacity(n);

    let send_start = Instant::now();
    for _ in 0..n {
        let (esk, epk) = secp.generate_keypair(rng);
        let ss_point = secp256k1::ecdh::shared_secret_point(viewing_pk, &esk);
        let ss: [u8; 32] = ss_point[..32].try_into().unwrap();
        let _stealth = stealth::derive_stealth_pubkey(spending_pk, &ss);
        let _tag = stealth::compute_view_tag(&ss);
        epks.push(epk);
    }
    let send = send_start.elapsed().as_micros() as u64;

    let recv_start = Instant::now();
    for epk in &epks {
        let ss_point = secp256k1::ecdh::shared_secret_point(epk, viewing_sk);
        let ss: [u8; 32] = ss_point[..32].try_into().unwrap();
        let _tag = stealth::compute_view_tag(&ss);
        let _stealth = stealth::derive_stealth_pubkey(spending_pk, &ss);
    }
    let recv = recv_start.elapsed().as_micros() as u64;

    (send, recv)
}

// =========================================================================
//  Direct ML-KEM: fresh ML-KEM-768 encapsulation per payment, 1088 B ct + 1 B view tag
// =========================================================================
fn bench_direct_mlkem(num_payments: usize, rng: &mut ChaChaRng) -> BenchResult {
    let secp = secp256k1::Secp256k1::new();
    let (_spending_sk, spending_pk) = secp.generate_keypair(rng);

    let mut seed_bytes = [0u8; 64];
    rng.fill_bytes(&mut seed_bytes);
    let dk = DecapsulationKey::<MlKem768>::from_seed(
        Seed::try_from(seed_bytes.as_slice()).unwrap(),
    );
    let ek = dk.encapsulation_key().clone();

    for _ in 0..WARMUP {
        direct_mlkem_send_recv(num_payments, &spending_pk, &ek, &dk, rng);
    }

    let mut send_us = Vec::new();
    let mut recv_us = Vec::new();
    for _ in 0..ITERS {
        let (s, r) = direct_mlkem_send_recv(num_payments, &spending_pk, &ek, &dk, rng);
        send_us.push(s);
        recv_us.push(r);
    }

    let calldata_per = 1089; // 1088 B ct + 1 B view tag
    let ann_gas = estimate_announcement_gas(calldata_per);

    BenchResult {
        model: "Direct KEM".into(),
        payments: num_payments,
        setup_calldata: 0,
        per_payment_calldata: calldata_per,
        total_calldata: calldata_per * num_payments,
        setup_gas: 0,
        per_payment_gas: ann_gas,
        total_gas: ann_gas * num_payments as u64,
        avg_send_us: send_us.iter().sum::<u64>() / ITERS as u64,
        avg_recv_us: recv_us.iter().sum::<u64>() / ITERS as u64,
    }
}

fn direct_mlkem_send_recv(
    n: usize,
    spending_pk: &secp256k1::PublicKey,
    ek: &ml_kem::ml_kem_768::EncapsulationKey,
    dk: &DecapsulationKey<MlKem768>,
    rng: &mut ChaChaRng,
) -> (u64, u64) {
    let mut cts = Vec::with_capacity(n);

    let send_start = Instant::now();
    for _ in 0..n {
        let mut m_bytes = [0u8; 32];
        rng.fill_bytes(&mut m_bytes);
        let (ct, ss) = ek.encapsulate_deterministic(
            &B32::try_from(m_bytes.as_slice()).unwrap(),
        );
        let ss_ref: &[u8] = ss.as_ref();
        let hk = Hkdf::<Sha256>::new(None, ss_ref);
        let mut derived = [0u8; 32];
        hk.expand(b"pq-sa-direct-v1", &mut derived).unwrap();
        let _stealth = stealth::derive_stealth_pubkey(spending_pk, &derived);
        let _tag = stealth::compute_view_tag(&derived);
        cts.push(ct);
    }
    let send = send_start.elapsed().as_micros() as u64;

    let recv_start = Instant::now();
    for ct in &cts {
        let ss = dk.decapsulate(ct);
        let ss_ref: &[u8] = ss.as_ref();
        let hk = Hkdf::<Sha256>::new(None, ss_ref);
        let mut derived = [0u8; 32];
        hk.expand(b"pq-sa-direct-v1", &mut derived).unwrap();
        let _tag = stealth::compute_view_tag(&derived);
        let _stealth = stealth::derive_stealth_pubkey(spending_pk, &derived);
    }
    let recv = recv_start.elapsed().as_micros() as u64;

    (send, recv)
}

// =========================================================================
//  Pairwise Channel: one-time hybrid KEM (1121 B), then 25 B memo per payment
// =========================================================================
fn bench_pairwise(num_payments: usize, rng: &mut ChaChaRng) -> BenchResult {
    let recipient = hybrid_kem::RecipientKeyPair::generate(rng);

    for _ in 0..WARMUP {
        pairwise_send_recv(num_payments, &recipient, rng);
    }

    let mut send_us = Vec::new();
    let mut recv_us = Vec::new();
    for _ in 0..ITERS {
        let (s, r) = pairwise_send_recv(num_payments, &recipient, rng);
        send_us.push(s);
        recv_us.push(r);
    }

    let setup_calldata = 1121; // 33 B ECDH + 1088 B ML-KEM
    let calldata_per = 25; // 16 B nonce + 1 B view tag + 8 B confirm tag
    let setup_gas = estimate_announcement_gas(setup_calldata);
    let memo_gas = estimate_announcement_gas(calldata_per);

    BenchResult {
        model: "Pairwise".into(),
        payments: num_payments,
        setup_calldata,
        per_payment_calldata: calldata_per,
        total_calldata: setup_calldata + calldata_per * num_payments,
        setup_gas,
        per_payment_gas: memo_gas,
        total_gas: setup_gas + memo_gas * num_payments as u64,
        avg_send_us: send_us.iter().sum::<u64>() / ITERS as u64,
        avg_recv_us: recv_us.iter().sum::<u64>() / ITERS as u64,
    }
}

fn pairwise_send_recv(
    n: usize,
    recipient: &hybrid_kem::RecipientKeyPair,
    rng: &mut ChaChaRng,
) -> (u64, u64) {
    let send_start = Instant::now();

    // First contact
    let (ct, k_pairwise) = hybrid_kem::encapsulate(
        &recipient.viewing.viewing_pk_ec, &recipient.viewing.ek_kem, rng,
    );

    // N payments using pairwise key
    let mut nonces = Vec::with_capacity(n);
    for _ in 0..n {
        let mut nonce = [0u8; 16];
        rng.fill_bytes(&mut nonce);
        let _stealth = stealth::derive_pairwise_stealth(
            &recipient.spending.spending_pk, None, &k_pairwise, &nonce,
        );
        nonces.push(nonce);
    }
    let send = send_start.elapsed().as_micros() as u64;

    // Recipient side
    let recv_start = Instant::now();
    let k_recv = hybrid_kem::decapsulate(&recipient.viewing, &ct).unwrap();
    for nonce in &nonces {
        let _stealth = stealth::derive_pairwise_stealth(
            &recipient.spending.spending_pk, Some(recipient.spending.spending_sk()), &k_recv, nonce,
        );
    }
    let recv = recv_start.elapsed().as_micros() as u64;

    (send, recv)
}

// =========================================================================
//  Scanning benchmark
// =========================================================================

/// Measures recipient scanning performance across all three models.
///
/// - Direct ML-KEM: decapsulate each ciphertext, derive stealth address, check view tag
/// - Pairwise: HKDF from k_pairwise + nonce, derive stealth address, check view tag
/// - Classical ECDH: ECDH per ephemeral key, derive stealth address, check view tag
///
/// The claim: "ML-KEM-768 decapsulation is ~10μs. Scanning 10K memos = ~0.1 seconds."
fn bench_scanning(rng: &mut ChaChaRng) {
    let scan_counts: &[usize] = &[100, 1_000, 10_000];

    let secp = secp256k1::Secp256k1::new();

    // --- Direct ML-KEM scanning ---
    {
        let (_spending_sk, spending_pk) = secp.generate_keypair(rng);
        let mut seed_bytes = [0u8; 64];
        rng.fill_bytes(&mut seed_bytes);
        let dk = DecapsulationKey::<MlKem768>::from_seed(
            Seed::try_from(seed_bytes.as_slice()).unwrap(),
        );
        let ek = dk.encapsulation_key().clone();

        println!("  Direct ML-KEM (decapsulate + stealth derive + view tag per memo):");
        for &n in scan_counts {
            // Pre-generate ciphertexts
            let mut cts = Vec::with_capacity(n);
            for _ in 0..n {
                let mut m_bytes = [0u8; 32];
                rng.fill_bytes(&mut m_bytes);
                let (ct, _ss) = ek.encapsulate_deterministic(
                    &B32::try_from(m_bytes.as_slice()).unwrap(),
                );
                cts.push(ct);
            }

            // Measure scanning
            let start = Instant::now();
            let mut matches = 0u32;
            for ct in &cts {
                let ss = dk.decapsulate(ct);
                let ss_ref: &[u8] = ss.as_ref();
                let hk = Hkdf::<Sha256>::new(None, ss_ref);
                let mut derived = [0u8; 32];
                hk.expand(b"pq-sa-direct-v1", &mut derived).unwrap();
                let tag = stealth::compute_view_tag(&derived);
                // Simulate: check view tag against a target (1/256 match rate)
                if tag == 0x42 { matches += 1; }
                let _stealth = stealth::derive_stealth_pubkey(&spending_pk, &derived);
            }
            let elapsed = start.elapsed();
            let per_memo_ns = elapsed.as_nanos() / n as u128;
            println!("    {:>6} memos: {:>8.2} ms  ({:.1} μs/memo, {} view tag matches)",
                n, elapsed.as_secs_f64() * 1000.0, per_memo_ns as f64 / 1000.0, matches);
        }
    }

    // --- Pairwise scanning ---
    {
        let recipient = hybrid_kem::RecipientKeyPair::generate(rng);
        let (ct, _k_sender) = hybrid_kem::encapsulate(
            &recipient.viewing.viewing_pk_ec, &recipient.viewing.ek_kem, rng,
        );
        let k_pairwise = hybrid_kem::decapsulate(&recipient.viewing, &ct).unwrap();

        println!("  Pairwise (HKDF + stealth derive + view tag per memo):");
        for &n in scan_counts {
            // Pre-generate nonces
            let mut nonces = Vec::with_capacity(n);
            for _ in 0..n {
                let mut nonce = [0u8; 16];
                rng.fill_bytes(&mut nonce);
                nonces.push(nonce);
            }

            let start = Instant::now();
            let mut matches = 0u32;
            for nonce in &nonces {
                let result = stealth::derive_pairwise_stealth(
                    &recipient.spending.spending_pk, Some(recipient.spending.spending_sk()), &k_pairwise, nonce,
                );
                if result.view_tag == 0x42 { matches += 1; }
            }
            let elapsed = start.elapsed();
            let per_memo_ns = elapsed.as_nanos() / n as u128;
            println!("    {:>6} memos: {:>8.2} ms  ({:.1} μs/memo, {} view tag matches)",
                n, elapsed.as_secs_f64() * 1000.0, per_memo_ns as f64 / 1000.0, matches);
        }
    }

    // --- Classical ECDH scanning ---
    {
        let (_spending_sk, spending_pk) = secp.generate_keypair(rng);
        let (viewing_sk, viewing_pk) = secp.generate_keypair(rng);

        println!("  Classical ECDH (ECDH + stealth derive + view tag per memo):");
        for &n in scan_counts {
            let mut epks = Vec::with_capacity(n);
            for _ in 0..n {
                let (_esk, epk) = secp.generate_keypair(rng);
                epks.push(epk);
            }

            // For classical, the recipient does ECDH with each ephemeral key
            // But we need to use the correct esk for sender side. Since we're
            // measuring recipient scanning, we pre-compute with sender's esk.
            // Recipient scanning = ECDH(viewing_sk, epk) per memo.
            let start = Instant::now();
            let mut matches = 0u32;
            for epk in &epks {
                let ss_point = secp256k1::ecdh::shared_secret_point(epk, &viewing_sk);
                let ss: [u8; 32] = ss_point[..32].try_into().unwrap();
                let tag = stealth::compute_view_tag(&ss);
                if tag == 0x42 { matches += 1; }
                let _stealth = stealth::derive_stealth_pubkey(&spending_pk, &ss);
            }
            let elapsed = start.elapsed();
            let per_memo_ns = elapsed.as_nanos() / n as u128;
            println!("    {:>6} memos: {:>8.2} ms  ({:.1} μs/memo, {} view tag matches)",
                n, elapsed.as_secs_f64() * 1000.0, per_memo_ns as f64 / 1000.0, matches);
        }
    }

    // --- Raw ML-KEM-768 decapsulation only ---
    {
        let mut seed_bytes = [0u8; 64];
        rng.fill_bytes(&mut seed_bytes);
        let dk = DecapsulationKey::<MlKem768>::from_seed(
            Seed::try_from(seed_bytes.as_slice()).unwrap(),
        );
        let ek = dk.encapsulation_key().clone();

        let n = 10_000;
        let mut cts = Vec::with_capacity(n);
        for _ in 0..n {
            let mut m_bytes = [0u8; 32];
            rng.fill_bytes(&mut m_bytes);
            let (ct, _ss) = ek.encapsulate_deterministic(
                &B32::try_from(m_bytes.as_slice()).unwrap(),
            );
            cts.push(ct);
        }

        let start = Instant::now();
        for ct in &cts {
            let _ss = dk.decapsulate(ct);
        }
        let elapsed = start.elapsed();
        let per_ns = elapsed.as_nanos() / n as u128;
        println!("  Raw ML-KEM-768 decapsulation only (10K):");
        println!("    {:>6} decaps: {:>7.2} ms  ({:.1} μs/decap)",
            n, elapsed.as_secs_f64() * 1000.0, per_ns as f64 / 1000.0);
    }

    println!();
}

// =========================================================================
//  SVG chart generation
// =========================================================================
fn generate_svg(results: &[BenchResult]) {
    let w = 800.0f64;
    let h = 500.0;
    let ml = 90.0;
    let mr = 30.0;
    let mt = 60.0;
    let mb = 80.0;
    let pw = w - ml - mr;
    let ph = h - mt - mb;

    let max_n = *PAYMENT_COUNTS.last().unwrap() as f64;

    // Gas per payment chart (including ETH transfer)
    let classical: Vec<(usize, u64)> = results.iter()
        .filter(|r| r.model == "Classical")
        .map(|r| (r.payments, r.total_gas / r.payments as u64 + GAS_ETH_TRANSFER))
        .collect();
    let direct: Vec<(usize, u64)> = results.iter()
        .filter(|r| r.model == "Direct KEM")
        .map(|r| (r.payments, r.total_gas / r.payments as u64 + GAS_ETH_TRANSFER))
        .collect();
    let pairwise: Vec<(usize, u64)> = results.iter()
        .filter(|r| r.model == "Pairwise")
        .map(|r| (r.payments, r.total_gas / r.payments as u64 + GAS_ETH_TRANSFER))
        .collect();

    let max_gas = direct.iter().map(|d| d.1).max().unwrap_or(1) as f64 * 1.15;

    let x = |n: usize| -> f64 { ml + (n as f64 / max_n) * pw };
    let y = |g: u64| -> f64 { mt + ph - (g as f64 / max_gas) * ph };

    let mut svg = format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {} {}" font-family="monospace" font-size="12">
  <rect width="{}" height="{}" fill="white"/>
  <text x="{}" y="30" font-size="15" font-weight="bold" text-anchor="middle">Average Gas per Payment (announcement + ETH transfer)</text>
"#, w, h, w, h, w / 2.0);

    // Grid
    for i in 0..=5 {
        let gy = mt + ph * (1.0 - i as f64 / 5.0);
        let val = (max_gas * i as f64 / 5.0) as u64;
        svg += &format!(
            r#"  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="silver"/>
  <text x="{}" y="{}" text-anchor="end" fill="gray">{}</text>
"#, ml, gy, w - mr, gy, ml - 8.0, gy + 4.0, val);
    }

    for &n in PAYMENT_COUNTS {
        svg += &format!(
            r#"  <text x="{}" y="{}" text-anchor="middle" fill="gray">{}</text>
"#, x(n), h - mb + 20.0, n);
    }
    svg += &format!(
        r#"  <text x="{}" y="{}" text-anchor="middle" font-size="13">Number of Payments (same recipient)</text>
  <text x="15" y="{}" text-anchor="middle" font-size="13" transform="rotate(-90, 15, {})">Gas per Payment</text>
"#, w / 2.0, h - 10.0, mt + ph / 2.0, mt + ph / 2.0);

    // Lines
    let colors = [("gray", &classical), ("crimson", &direct), ("steelblue", &pairwise)];
    for (color, data) in &colors {
        let points: String = data.iter()
            .map(|&(n, g)| format!("{:.1},{:.1}", x(n), y(g)))
            .collect::<Vec<_>>().join(" ");
        svg += &format!(r#"  <polyline points="{}" fill="none" stroke="{}" stroke-width="2.5"/>
"#, points, color);
        for &(n, g) in *data {
            svg += &format!(r#"  <circle cx="{:.1}" cy="{:.1}" r="4" fill="{}"/>
"#, x(n), y(g), color);
        }
    }

    // Legend
    let lx = ml + 20.0;
    let ly = mt + 20.0;
    svg += &format!(
        r#"  <rect x="{}" y="{}" width="280" height="75" fill="white" stroke="silver" rx="4"/>
  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="gray" stroke-width="2.5"/>
  <text x="{}" y="{}" font-size="11">Classical ERC-5564 (33 B ECDH, no PQ)</text>
  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="crimson" stroke-width="2.5"/>
  <text x="{}" y="{}" font-size="11">Direct ML-KEM (1,089 B per payment)</text>
  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="steelblue" stroke-width="2.5"/>
  <text x="{}" y="{}" font-size="11">Pairwise channel (25 B per payment)</text>
"#,
        lx, ly,
        lx + 10.0, ly + 16.0, lx + 40.0, ly + 16.0,
        lx + 48.0, ly + 20.0,
        lx + 10.0, ly + 36.0, lx + 40.0, ly + 36.0,
        lx + 48.0, ly + 40.0,
        lx + 10.0, ly + 56.0, lx + 40.0, ly + 56.0,
        lx + 48.0, ly + 60.0,
    );

    svg += "</svg>\n";
    std::fs::write("bench_gas_comparison.svg", &svg).unwrap();
    println!("\nChart saved to bench_gas_comparison.svg");

    // Calldata chart
    generate_calldata_svg(results);
}

fn generate_calldata_svg(results: &[BenchResult]) {
    let w = 800.0f64;
    let h = 500.0;
    let ml = 90.0;
    let mr = 30.0;
    let mt = 60.0;
    let mb = 80.0;
    let pw = w - ml - mr;
    let ph = h - mt - mb;
    let max_n = *PAYMENT_COUNTS.last().unwrap() as f64;

    let classical: Vec<(usize, usize)> = results.iter()
        .filter(|r| r.model == "Classical")
        .map(|r| (r.payments, r.total_calldata))
        .collect();
    let direct: Vec<(usize, usize)> = results.iter()
        .filter(|r| r.model == "Direct KEM")
        .map(|r| (r.payments, r.total_calldata))
        .collect();
    let pairwise: Vec<(usize, usize)> = results.iter()
        .filter(|r| r.model == "Pairwise")
        .map(|r| (r.payments, r.total_calldata))
        .collect();

    let max_data = direct.iter().map(|d| d.1).max().unwrap_or(1) as f64 * 1.15;

    let x = |n: usize| -> f64 { ml + (n as f64 / max_n) * pw };
    let y = |d: usize| -> f64 { mt + ph - (d as f64 / max_data) * ph };

    let mut svg = format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {} {}" font-family="monospace" font-size="12">
  <rect width="{}" height="{}" fill="white"/>
  <text x="{}" y="30" font-size="15" font-weight="bold" text-anchor="middle">Total Calldata: Classical vs Direct ML-KEM vs Pairwise</text>
"#, w, h, w, h, w / 2.0);

    for i in 0..=5 {
        let gy = mt + ph * (1.0 - i as f64 / 5.0);
        let val = (max_data * i as f64 / 5.0) as usize;
        svg += &format!(
            r#"  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="silver"/>
  <text x="{}" y="{}" text-anchor="end" fill="gray">{}</text>
"#, ml, gy, w - mr, gy, ml - 8.0, gy + 4.0, val);
    }
    for &n in PAYMENT_COUNTS {
        svg += &format!(r#"  <text x="{}" y="{}" text-anchor="middle" fill="gray">{}</text>
"#, x(n), h - mb + 20.0, n);
    }
    svg += &format!(
        r#"  <text x="{}" y="{}" text-anchor="middle" font-size="13">Number of Payments</text>
  <text x="15" y="{}" text-anchor="middle" font-size="13" transform="rotate(-90, 15, {})">Total Calldata (bytes)</text>
"#, w / 2.0, h - 10.0, mt + ph / 2.0, mt + ph / 2.0);

    let colors = [("gray", &classical), ("crimson", &direct), ("steelblue", &pairwise)];
    for (color, data) in &colors {
        let points: String = data.iter()
            .map(|&(n, d)| format!("{:.1},{:.1}", x(n), y(d)))
            .collect::<Vec<_>>().join(" ");
        svg += &format!(r#"  <polyline points="{}" fill="none" stroke="{}" stroke-width="2.5"/>
"#, points, color);
        for &(n, d) in *data {
            svg += &format!(r#"  <circle cx="{:.1}" cy="{:.1}" r="4" fill="{}"/>
"#, x(n), y(d), color);
        }
    }

    let lx = ml + 20.0;
    let ly = mt + 20.0;
    svg += &format!(
        r#"  <rect x="{}" y="{}" width="280" height="75" fill="white" stroke="silver" rx="4"/>
  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="gray" stroke-width="2.5"/>
  <text x="{}" y="{}" font-size="11">Classical (34 B per payment)</text>
  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="crimson" stroke-width="2.5"/>
  <text x="{}" y="{}" font-size="11">Direct ML-KEM (1,089 B per payment)</text>
  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="steelblue" stroke-width="2.5"/>
  <text x="{}" y="{}" font-size="11">Pairwise (1,121 B setup + 25 B per)</text>
"#,
        lx, ly,
        lx + 10.0, ly + 16.0, lx + 40.0, ly + 16.0,
        lx + 48.0, ly + 20.0,
        lx + 10.0, ly + 36.0, lx + 40.0, ly + 36.0,
        lx + 48.0, ly + 40.0,
        lx + 10.0, ly + 56.0, lx + 40.0, ly + 56.0,
        lx + 48.0, ly + 60.0,
    );

    svg += "</svg>\n";
    std::fs::write("bench_calldata_comparison.svg", &svg).unwrap();
    println!("Chart saved to bench_calldata_comparison.svg");
}
