//! Benchmarks: baseline ML-KEM vs PQ-SA (hybrid KEM + pairwise channels).
//! Measures CPU time for crypto operations and outputs data for graphing.
//! Gas costs are computed analytically from calldata sizes (16 gas/nonzero byte + 4 gas/zero byte).

use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use chacha20poly1305::aead::Aead;
use hkdf::Hkdf;
use ml_kem::ml_kem_768::MlKem768;
use ml_kem::{B32, Seed, DecapsulationKey, EncapsulationKey, Decapsulate};
use primitives::*;
use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use serde::Serialize;
use sha2::Sha256;
use std::time::Instant;

const NOTE_COUNTS: &[usize] = &[1, 2, 5, 10, 20, 50];
const WARMUP: usize = 3;
const ITERS: usize = 10;

// Estimated gas: 21000 base + 16 per nonzero calldata byte + overhead
// Calibrated against actual Sepolia measurements
const GAS_BASE: u64 = 30_000; // contract call overhead (approx)
const GAS_PER_BYTE: u64 = 16; // nonzero calldata byte

#[derive(Serialize)]
struct BenchResult {
    approach: String,
    notes: usize,
    total_send_us: u64,
    total_recv_us: u64,
    avg_send_us: u64,
    avg_recv_us: u64,
    total_calldata_bytes: usize,
    total_gas: u64,
    avg_gas_per_note: u64,
}

fn main() {
    let mut rng = ChaChaRng::seed_from_u64(42);

    println!("==========================================================");
    println!("  Benchmark: Baseline ML-KEM vs PQ-SA Hybrid");
    println!("==========================================================\n");

    let mut results: Vec<BenchResult> = Vec::new();

    for &n in NOTE_COUNTS {
        let baseline = bench_baseline(n, &mut rng);
        let pqibsd = bench_pqibsd(n, &mut rng);
        results.push(baseline);
        results.push(pqibsd);
    }

    // Print table
    println!("\n{:<12} {:>5} {:>12} {:>12} {:>12} {:>10} {:>10}",
        "Approach", "Notes", "Send(us)", "Recv(us)", "Calldata(B)", "Gas", "Gas/note");
    println!("{}", "-".repeat(85));

    for r in &results {
        println!("{:<12} {:>5} {:>12} {:>12} {:>12} {:>10} {:>10}",
            r.approach, r.notes, r.total_send_us, r.total_recv_us,
            r.total_calldata_bytes, r.total_gas, r.avg_gas_per_note);
    }

    // Print savings
    println!("\n--- Savings (PQ-SA vs baseline) ---\n");
    println!("{:>5} {:>12} {:>12} {:>12}", "Notes", "Gas saved", "Data saved", "Send speedup");
    println!("{}", "-".repeat(50));

    for chunk in results.chunks(2) {
        if chunk.len() == 2 {
            let bl = &chunk[0];
            let pq = &chunk[1];
            let gas_pct = (1.0 - pq.total_gas as f64 / bl.total_gas as f64) * 100.0;
            let data_pct = (1.0 - pq.total_calldata_bytes as f64 / bl.total_calldata_bytes as f64) * 100.0;
            let send_ratio = bl.total_send_us as f64 / pq.total_send_us as f64;
            println!("{:>5} {:>10.1}% {:>10.1}% {:>10.1}x",
                bl.notes, gas_pct, data_pct, send_ratio);
        }
    }

    // Output JSON for graphing
    let json_path = "bench_results.json";
    let json = serde_json::to_string_pretty(&results).unwrap();
    std::fs::write(json_path, &json).unwrap();
    println!("\nResults saved to {}", json_path);

    // Generate SVG chart
    generate_svg(&results);
}

fn bench_baseline(num_notes: usize, rng: &mut ChaChaRng) -> BenchResult {
    // Setup: recipient keygen
    let mut seed_bytes = [0u8; 64];
    rng.fill_bytes(&mut seed_bytes);
    let dk = DecapsulationKey::<MlKem768>::from_seed(
        Seed::try_from(seed_bytes.as_slice()).unwrap(),
    );
    let ek = dk.encapsulation_key().clone();

    // Warmup
    for _ in 0..WARMUP {
        baseline_send_recv(num_notes, &ek, &dk, rng);
    }

    // Measure
    let mut send_times = Vec::with_capacity(ITERS);
    let mut recv_times = Vec::with_capacity(ITERS);
    let mut calldata_total = 0usize;

    for _ in 0..ITERS {
        let (st, rt, cd) = baseline_send_recv(num_notes, &ek, &dk, rng);
        send_times.push(st);
        recv_times.push(rt);
        calldata_total = cd;
    }

    let avg_send = send_times.iter().sum::<u64>() / ITERS as u64;
    let avg_recv = recv_times.iter().sum::<u64>() / ITERS as u64;
    let total_gas = GAS_BASE * num_notes as u64 + GAS_PER_BYTE * calldata_total as u64;

    BenchResult {
        approach: "baseline".into(),
        notes: num_notes,
        total_send_us: avg_send,
        total_recv_us: avg_recv,
        avg_send_us: avg_send / num_notes as u64,
        avg_recv_us: avg_recv / num_notes as u64,
        total_calldata_bytes: calldata_total,
        total_gas,
        avg_gas_per_note: total_gas / num_notes as u64,
    }
}

fn baseline_send_recv(
    num_notes: usize,
    ek: &EncapsulationKey<MlKem768>,
    dk: &DecapsulationKey<MlKem768>,
    rng: &mut ChaChaRng,
) -> (u64, u64, usize) {
    let mut payloads = Vec::with_capacity(num_notes);
    let mut total_calldata = 0usize;

    // SEND: fresh KEM per note
    let send_start = Instant::now();
    for i in 0..num_notes {
        let mut m_bytes = [0u8; 32];
        rng.fill_bytes(&mut m_bytes);
        let (ct_pq, ss_pq) = ek.encapsulate_deterministic(
            &B32::try_from(m_bytes.as_slice()).unwrap(),
        );

        let ss_ref: &[u8] = ss_pq.as_ref();
        let hk = Hkdf::<Sha256>::new(None, ss_ref);
        let mut key = [0u8; 32];
        hk.expand(b"baseline-mlkem", &mut key).unwrap();

        let mut plaintext = [0u8; 616];
        plaintext[0..8].copy_from_slice(&((i as u64 + 1) * 100_000).to_le_bytes());
        rng.fill_bytes(&mut plaintext[40..72]);

        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
        let ct_data = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        let ct_pq_ref: &[u8] = ct_pq.as_ref();
        // Payload: ct_pq(1088) + nonce(12) + ciphertext(632)
        let payload_len = ct_pq_ref.len() + 12 + ct_data.len();
        total_calldata += payload_len + 32; // + commitment

        payloads.push((ct_pq_ref.to_vec(), nonce_bytes, ct_data));
    }
    let send_us = send_start.elapsed().as_micros() as u64;

    // RECV: decapsulate + decrypt each
    let recv_start = Instant::now();
    for (ct_pq_bytes, nonce_bytes, ct_data) in &payloads {
        let ct_pq = ml_kem::ml_kem_768::Ciphertext::try_from(ct_pq_bytes.as_slice()).unwrap();
        let ss_pq = dk.decapsulate(&ct_pq);

        let ss_ref: &[u8] = ss_pq.as_ref();
        let hk = Hkdf::<Sha256>::new(None, ss_ref);
        let mut key = [0u8; 32];
        hk.expand(b"baseline-mlkem", &mut key).unwrap();

        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes);
        let _plaintext = cipher.decrypt(nonce, ct_data.as_ref()).unwrap();
    }
    let recv_us = recv_start.elapsed().as_micros() as u64;

    (send_us, recv_us, total_calldata)
}

fn bench_pqibsd(num_notes: usize, rng: &mut ChaChaRng) -> BenchResult {
    let recipient = hybrid_kem::RecipientKeyPair::generate(rng);

    // Warmup
    for _ in 0..WARMUP {
        pqibsd_send_recv(num_notes, &recipient, rng);
    }

    let mut send_times = Vec::with_capacity(ITERS);
    let mut recv_times = Vec::with_capacity(ITERS);
    let mut calldata_total = 0usize;

    for _ in 0..ITERS {
        let (st, rt, cd) = pqibsd_send_recv(num_notes, &recipient, rng);
        send_times.push(st);
        recv_times.push(rt);
        calldata_total = cd;
    }

    let avg_send = send_times.iter().sum::<u64>() / ITERS as u64;
    let avg_recv = recv_times.iter().sum::<u64>() / ITERS as u64;
    let total_gas = GAS_BASE * num_notes as u64 + GAS_PER_BYTE * calldata_total as u64;

    BenchResult {
        approach: "PQ-SA".into(),
        notes: num_notes,
        total_send_us: avg_send,
        total_recv_us: avg_recv,
        avg_send_us: avg_send / num_notes as u64,
        avg_recv_us: avg_recv / num_notes as u64,
        total_calldata_bytes: calldata_total,
        total_gas,
        avg_gas_per_note: total_gas / num_notes as u64,
    }
}

fn pqibsd_send_recv(
    num_notes: usize,
    recipient: &hybrid_kem::RecipientKeyPair,
    rng: &mut ChaChaRng,
) -> (u64, u64, usize) {
    let mut total_calldata = 0usize;

    // SEND
    let send_start = Instant::now();

    // First contact: hybrid KEM
    let (first_ct, k_pairwise) = hybrid_kem::encapsulate(
        &recipient.pk_ec, &recipient.ek_kem, rng,
    );

    let mut nonce0 = [0u8; 16];
    rng.fill_bytes(&mut nonce0);
    let plaintext0 = note::NotePlaintext {
        value: 100_000,
        asset_id: [1u8; 32],
        blinding_factor: { let mut b = [0u8; 32]; rng.fill_bytes(&mut b); b },
        memo: [0u8; 512],
        nullifier_seed: commitment::nullifier_seed(&k_pairwise, &nonce0),
    };
    let ser0 = plaintext0.serialize();
    let ct0 = aead::encrypt(&k_pairwise, &nonce0, &ser0).unwrap();

    // First contact calldata: epk(33) + ct_pq(1088) + nonce(16) + ct(632) + commitment(32)
    total_calldata += 33 + first_ct.ct_pq.len() + 16 + ct0.len() + 32;

    // Subsequent notes: known-pair, only nonce + ciphertext + commitment
    let mut known_pair_data = Vec::with_capacity(num_notes - 1);
    for i in 1..num_notes {
        let mut nonce_n = [0u8; 16];
        rng.fill_bytes(&mut nonce_n);
        let note_n = note::NotePlaintext {
            value: (i as u64 + 1) * 100_000,
            asset_id: [1u8; 32],
            blinding_factor: { let mut b = [0u8; 32]; rng.fill_bytes(&mut b); b },
            memo: [0u8; 512],
            nullifier_seed: commitment::nullifier_seed(&k_pairwise, &nonce_n),
        };
        let ser_n = note_n.serialize();
        let ct_n = aead::encrypt(&k_pairwise, &nonce_n, &ser_n).unwrap();

        // Known-pair calldata: commitment(32) + nonce(16) + ciphertext(632)
        total_calldata += 32 + 16 + ct_n.len();
        known_pair_data.push((nonce_n, ct_n));
    }
    let send_us = send_start.elapsed().as_micros() as u64;

    // RECV
    let recv_start = Instant::now();

    // Decapsulate first contact
    let k_recv = hybrid_kem::decapsulate(recipient, &first_ct).unwrap();
    let _dec0 = aead::decrypt(&k_recv, &nonce0, &ct0).unwrap();

    // Decrypt known-pair notes (symmetric only — no KEM)
    for (nonce_n, ct_n) in &known_pair_data {
        let _dec_n = aead::decrypt(&k_recv, nonce_n, ct_n).unwrap();
    }
    let recv_us = recv_start.elapsed().as_micros() as u64;

    (send_us, recv_us, total_calldata)
}

fn generate_svg(results: &[BenchResult]) {
    let w = 800.0f64;
    let h = 500.0;
    let margin_l = 80.0;
    let margin_r = 30.0;
    let margin_t = 60.0;
    let margin_b = 80.0;
    let plot_w = w - margin_l - margin_r;
    let plot_h = h - margin_t - margin_b;

    // Extract data for gas/note chart
    let baseline: Vec<(usize, u64)> = results.iter()
        .filter(|r| r.approach == "baseline")
        .map(|r| (r.notes, r.avg_gas_per_note))
        .collect();
    let pqibsd: Vec<(usize, u64)> = results.iter()
        .filter(|r| r.approach == "PQ-SA")
        .map(|r| (r.notes, r.avg_gas_per_note))
        .collect();

    let max_notes = *NOTE_COUNTS.last().unwrap() as f64;
    let max_gas = baseline.iter().map(|b| b.1).max().unwrap_or(1) as f64 * 1.15;

    let x = |n: usize| -> f64 { margin_l + (n as f64 / max_notes) * plot_w };
    let y = |g: u64| -> f64 { margin_t + plot_h - (g as f64 / max_gas) * plot_h };

    let mut svg = format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {} {}" font-family="monospace" font-size="12">
  <rect width="{}" height="{}" fill="white"/>
  <text x="{}" y="30" font-size="16" font-weight="bold" text-anchor="middle">Average Gas per Note: Baseline ML-KEM vs PQ-SA</text>
"#, w, h, w, h, w / 2.0);

    // Grid lines
    for i in 0..=5 {
        let gy = margin_t + plot_h * (1.0 - i as f64 / 5.0);
        let val = (max_gas * i as f64 / 5.0) as u64;
        svg += &format!(
            r#"  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="silver"/>
  <text x="{}" y="{}" text-anchor="end" fill="gray">{}</text>
"#, margin_l, gy, w - margin_r, gy, margin_l - 8.0, gy + 4.0, val);
    }

    // X axis labels
    for &n in NOTE_COUNTS {
        let xp = x(n);
        svg += &format!(
            r#"  <text x="{}" y="{}" text-anchor="middle" fill="gray">{}</text>
"#, xp, h - margin_b + 20.0, n);
    }
    svg += &format!(
        r#"  <text x="{}" y="{}" text-anchor="middle" font-size="13">Number of Notes</text>
  <text x="15" y="{}" text-anchor="middle" font-size="13" transform="rotate(-90, 15, {})">Gas per Note</text>
"#, w / 2.0, h - 10.0, margin_t + plot_h / 2.0, margin_t + plot_h / 2.0);

    // Baseline line (red)
    let mut bl_path = String::from("M");
    for (i, &(n, g)) in baseline.iter().enumerate() {
        let sep = if i == 0 { "" } else { " L" };
        bl_path += &format!("{}{:.1},{:.1}", sep, x(n), y(g));
    }
    svg += &format!(
        r#"  <polyline points="{}" fill="none" stroke="crimson" stroke-width="2.5"/>
"#, bl_path.replace("M", "").replace(" L", " "));

    // Baseline dots
    for &(n, g) in &baseline {
        svg += &format!(
            r#"  <circle cx="{:.1}" cy="{:.1}" r="4" fill="crimson"/>
"#, x(n), y(g));
    }

    // PQ-SA line (blue)
    let mut pq_path = String::new();
    for (i, &(n, g)) in pqibsd.iter().enumerate() {
        let sep = if i == 0 { "" } else { " " };
        pq_path += &format!("{}{:.1},{:.1}", sep, x(n), y(g));
    }
    svg += &format!(
        r#"  <polyline points="{}" fill="none" stroke="steelblue" stroke-width="2.5"/>
"#, pq_path);

    // PQ-SA dots
    for &(n, g) in &pqibsd {
        svg += &format!(
            r#"  <circle cx="{:.1}" cy="{:.1}" r="4" fill="steelblue"/>
"#, x(n), y(g));
    }

    // Legend
    let lx = margin_l + 20.0;
    let ly = margin_t + 20.0;
    svg += &format!(
        r#"  <rect x="{}" y="{}" width="240" height="55" fill="white" stroke="silver" rx="4"/>
  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="crimson" stroke-width="2.5"/>
  <circle cx="{}" cy="{}" r="3" fill="crimson"/>
  <text x="{}" y="{}" font-size="12">Baseline (fresh ML-KEM per note)</text>
  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="steelblue" stroke-width="2.5"/>
  <circle cx="{}" cy="{}" r="3" fill="steelblue"/>
  <text x="{}" y="{}" font-size="12">PQ-SA (hybrid KEM + pairwise)</text>
"#,
        lx, ly,
        lx + 10.0, ly + 18.0, lx + 40.0, ly + 18.0,
        lx + 25.0, ly + 18.0,
        lx + 48.0, ly + 22.0,
        lx + 10.0, ly + 40.0, lx + 40.0, ly + 40.0,
        lx + 25.0, ly + 40.0,
        lx + 48.0, ly + 44.0,
    );

    svg += "</svg>\n";

    let svg_path = "bench_gas_comparison.svg";
    std::fs::write(svg_path, &svg).unwrap();
    println!("\nChart saved to {}", svg_path);

    // Also generate calldata chart
    generate_calldata_svg(results);
}

fn generate_calldata_svg(results: &[BenchResult]) {
    let w = 800.0f64;
    let h = 500.0;
    let margin_l = 80.0;
    let margin_r = 30.0;
    let margin_t = 60.0;
    let margin_b = 80.0;
    let plot_w = w - margin_l - margin_r;
    let plot_h = h - margin_t - margin_b;

    let baseline: Vec<(usize, usize)> = results.iter()
        .filter(|r| r.approach == "baseline")
        .map(|r| (r.notes, r.total_calldata_bytes))
        .collect();
    let pqibsd: Vec<(usize, usize)> = results.iter()
        .filter(|r| r.approach == "PQ-SA")
        .map(|r| (r.notes, r.total_calldata_bytes))
        .collect();

    let max_notes = *NOTE_COUNTS.last().unwrap() as f64;
    let max_data = baseline.iter().map(|b| b.1).max().unwrap_or(1) as f64 * 1.15;

    let x = |n: usize| -> f64 { margin_l + (n as f64 / max_notes) * plot_w };
    let y = |d: usize| -> f64 { margin_t + plot_h - (d as f64 / max_data) * plot_h };

    let mut svg = format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {} {}" font-family="monospace" font-size="12">
  <rect width="{}" height="{}" fill="white"/>
  <text x="{}" y="30" font-size="16" font-weight="bold" text-anchor="middle">Total Calldata: Baseline ML-KEM vs PQ-SA</text>
"#, w, h, w, h, w / 2.0);

    // Grid
    for i in 0..=5 {
        let gy = margin_t + plot_h * (1.0 - i as f64 / 5.0);
        let val = (max_data * i as f64 / 5.0) as usize;
        svg += &format!(
            r#"  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="silver"/>
  <text x="{}" y="{}" text-anchor="end" fill="gray">{}</text>
"#, margin_l, gy, w - margin_r, gy, margin_l - 8.0, gy + 4.0, val);
    }

    for &n in NOTE_COUNTS {
        svg += &format!(
            r#"  <text x="{}" y="{}" text-anchor="middle" fill="gray">{}</text>
"#, x(n), h - margin_b + 20.0, n);
    }
    svg += &format!(
        r#"  <text x="{}" y="{}" text-anchor="middle" font-size="13">Number of Notes</text>
  <text x="15" y="{}" text-anchor="middle" font-size="13" transform="rotate(-90, 15, {})">Total Calldata (bytes)</text>
"#, w / 2.0, h - 10.0, margin_t + plot_h / 2.0, margin_t + plot_h / 2.0);

    // Baseline (red)
    let points_bl: String = baseline.iter()
        .map(|&(n, d)| format!("{:.1},{:.1}", x(n), y(d)))
        .collect::<Vec<_>>().join(" ");
    svg += &format!(r#"  <polyline points="{}" fill="none" stroke="crimson" stroke-width="2.5"/>
"#, points_bl);
    for &(n, d) in &baseline {
        svg += &format!(r#"  <circle cx="{:.1}" cy="{:.1}" r="4" fill="crimson"/>
"#, x(n), y(d));
    }

    // PQ-SA (blue)
    let points_pq: String = pqibsd.iter()
        .map(|&(n, d)| format!("{:.1},{:.1}", x(n), y(d)))
        .collect::<Vec<_>>().join(" ");
    svg += &format!(r#"  <polyline points="{}" fill="none" stroke="steelblue" stroke-width="2.5"/>
"#, points_pq);
    for &(n, d) in &pqibsd {
        svg += &format!(r#"  <circle cx="{:.1}" cy="{:.1}" r="4" fill="steelblue"/>
"#, x(n), y(d));
    }

    // Legend
    let lx = margin_l + 20.0;
    let ly = margin_t + 20.0;
    svg += &format!(
        r#"  <rect x="{}" y="{}" width="240" height="55" fill="white" stroke="silver" rx="4"/>
  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="crimson" stroke-width="2.5"/>
  <text x="{}" y="{}" font-size="12">Baseline (1088 B KEM ct per note)</text>
  <line x1="{}" y1="{}" x2="{}" y2="{}" stroke="steelblue" stroke-width="2.5"/>
  <text x="{}" y="{}" font-size="12">PQ-SA (KEM ct only on 1st note)</text>
"#,
        lx, ly,
        lx + 10.0, ly + 18.0, lx + 40.0, ly + 18.0,
        lx + 48.0, ly + 22.0,
        lx + 10.0, ly + 40.0, lx + 40.0, ly + 40.0,
        lx + 48.0, ly + 44.0,
    );

    svg += "</svg>\n";

    let path = "bench_calldata_comparison.svg";
    std::fs::write(path, &svg).unwrap();
    println!("Chart saved to {}", path);
}
