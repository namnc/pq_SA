# pq_SA

**Post-Quantum Key Exchange for Ethereum Stealth Addresses**

**Experimental research PoC.** Hybrid KEM (ECDH + ML-KEM-768) for Ethereum stealth addresses, preserving viewing/spending separation via EC scalar addition. The hybrid provides transitional security: if either ECDH or ML-KEM holds, the pairwise key is secure. Two models: direct ML-KEM (baseline) and pairwise hybrid channel (calldata optimization). Depends on pre-release `ml-kem = 0.3.0-rc.1` (unaudited).

## The Design

### Classical stealth address (ERC-5564)

```
Sender: shared_secret = ECDH(ephemeral_sk, viewing_pk)         ← 33 B ephemeral key
        stealth_pk = spending_pk + hash(ss) * G
        send ETH to address(stealth_pk)

Server: shared_secret = ECDH(viewing_sk, ephemeral_pk)         ← can detect
        stealth_pk = spending_pk + hash(ss) * G                ← cannot spend (no spending_sk)

Recipient: stealth_sk = spending_sk + hash(ss)                 ← can spend
```

### Model 1: Direct ML-KEM stealth (drop-in PQ replacement)

Replace ECDH with ML-KEM. Everything else stays the same.

```
Sender: (ct, ss) = ML-KEM.Encaps(viewing_ek)                  ← 1,088 B ciphertext
        stealth_pk = spending_pk + hash(ss) * G                ← same EC algebra
        posts ct + view_tag (1 B) on-chain
        sends ETH to address(stealth_pk)

Server: ss = ML-KEM.Decaps(viewing_dk, ct)                    ← can detect
        view_tag check: hash(ss)[0] == tag? (99.6% filter)
        stealth_pk = spending_pk + hash(ss) * G                ← cannot spend

Recipient: stealth_sk = spending_sk + hash(ss)                 ← can spend (Ethereum sig)
```

**Viewing/spending separation preserved**: the server has `viewing_dk` and can compute `hash(ss)`, but `stealth_sk = spending_sk + hash(ss)` requires `spending_sk` (private). Delegation is safe.

**Scanning is fast**: ML-KEM-768 decapsulation is ~36μs. Scanning 10K memos takes ~0.8s (direct) or ~0.4s (pairwise). View tags further reduce work by 99.6%.

### Model 2: Pairwise channel (calldata optimization)

The 1,088 B ciphertext appears once per sender-recipient pair, then amortizes to zero.

```
First contact (one-time):
  Hybrid KEM: ECDH + ML-KEM-768 → k_pairwise              ← 1,121 B (33 + 1,088)

Per payment:
  ss = SHA-256("pq-sa-pairwise-stealth-v1" || k_pairwise || nonce)
  stealth_pk = spending_pk + SHA-256("pq-sa-stealth-derive-v1" || ss) * G
  posts memo(nonce) on-chain                                ← 18 B
  sends ETH to address(stealth_pk)
```

**Non-interactive**: the sender only needs the recipient's public keys from the on-chain `KeyRegistered` event. First contact and first payment can happen in the same block — no round-trip with the recipient. The recipient catches up later by scanning events.

### Harvest-Now-Decrypt-Later Defense

Classical ERC-5564 is vulnerable to HNDL: an adversary records ECDH ephemeral keys on-chain today and breaks them later with a quantum computer, linking all stealth addresses to recipients.

The hybrid KEM in the pairwise first contact defeats this. A quantum attacker can break the ECDH component but not ML-KEM-768. Since `k_pairwise = HKDF(ECDH_ss || ML-KEM_ss)`, both are required — all derived stealth addresses remain hidden.

### Wallet Recovery

The recipient stores only a 32-byte seed. Keys are deterministic: `seed → (spending_sk, viewing_sk_ec, viewing_dk)`. First contact ciphertexts are permanently on-chain. Recovery:

1. Re-derive keys from seed
2. Scan `FirstContact` events, decapsulate each → get candidate `k_pairwise` values
3. **Verify**: for each candidate, scan `Memo` events and check view tags. ML-KEM implicit rejection means decapsulation always returns a key — even for first contacts not addressed to you. Only genuine channels will have matching view tags among actual memos.
4. Confirmed channels' stealth addresses → check balances, sweep

Work scales with total first contacts × memos, not just your own channels. View tags (99.6% filter) keep per-memo verification fast. Tested in `test_wallet_recovery_from_seed`.

### Hardware Wallet Integration

The viewing/spending separation maps naturally to hardware wallets:

| Component | Where | Why |
|-----------|-------|-----|
| seed (32 B) | Hardware wallet | Derives all keys, never leaves device |
| spending_sk | Hardware wallet | Signs stealth transactions |
| viewing bundle (viewing_sk_ec + dk_kem) | Software wallet (phone/desktop) | Scans memos, detects payments — safe to export (can't spend) |

The viewing bundle contains **both** the EC viewing secret (for ECDH) and the ML-KEM decapsulation key — both are needed to recover `k_pairwise` from first contacts. Exporting only one is insufficient.

**Cross-device**: any device with the viewing bundle can scan for payments. Only the hardware wallet can spend. A new device recovers by getting the viewing bundle from the hardware wallet, then scanning on-chain events — zero state transfer needed.

**Spending from a stealth address**: the software wallet computes `scalar = hash(shared_secret)` and sends it to the hardware wallet. The hardware wallet computes `stealth_sk = spending_sk + scalar`, verifies `spending_pk + scalar*G` matches the expected stealth address, and signs.

### Comparison

| | Classical | Direct ML-KEM | Pairwise (our optimization) |
|--|----------|--------------|---------------------------|
| PQ key exchange | No | **Yes** | **Yes** |
| Viewing/spending separation | Yes | **Yes** | **Yes** |
| View tag (99.6% filter) | Yes | **Yes** | **Yes** |
| Safe server delegation | Yes | **Yes** | **Yes** |
| Spend auth | Ethereum sig | Ethereum sig | Ethereum sig |
| Calldata per payment | 34 B | 1,089 B | **18 B** (after first contact) |
| Announcement gas | ~47K | ~61K | **~34K** (after ~79K first contact) |
| ETH transfer gas | 21K | 21K | 21K |
| Scanning 10K memos (measured) | ~0.7s | ~0.8s | ~0.4s |

**PQ scope**: Stealth spending uses secp256k1. Full PQ spending needs EIP-7932. Our scope is PQ KEM for key exchange and payment discovery.

## Measured Gas (Anvil)

Calldata sizes below are **payload bytes** (the application data), not ABI-encoded wire calldata. ABI encoding adds function selector (4 B) and padding overhead, so actual on-wire calldata is larger. Gas numbers are measured on Anvil and include ABI overhead.

| Transaction | Gas (measured) | Payload |
|-------------|---------------|---------|
| Register keys (one-time) | 79,846 | 1,250 B (33 + 33 + 1,184) |
| First contact (one-time per pair) | 78,578 | 1,121 B |
| Memo (per payment) | 34,206 | 17 B (16 nonce + 1 view tag) |
| ETH transfer to stealth addr | 21,000 | 0 B |

ETH transfer is constant (21K gas) across all models. The announcement gas is what varies:

| Model | Announcement gas | Payload |
|-------|-----------------|---------|
| Classical ERC-5564 | ~47K (estimated) | 34 B |
| Direct ML-KEM | ~61K (estimated) | 1,089 B |
| Pairwise (per payment) | **34,206 (measured)** | **17 B** |

## Project Structure

```
pq_SA/
├── contracts/
│   ├── src/MemoRegistry.sol       Stealth address discovery log (14 Foundry tests)
│   └── test/MemoRegistry.t.sol
├── crates/
│   ├── primitives/
│   │   ├── src/
│   │   │   ├── hybrid_kem.rs      ECDH + ML-KEM-768 hybrid KEM
│   │   │   └── stealth.rs         EC algebra stealth derivation (Model 1 + 2)
│   │   └── tests/e2e.rs           5 integration tests (incl. delegation safety)
│   ├── demo/                      Full Anvil demo (stealth address flow)
│   └── bench/                     Gas + CPU benchmarks, SVG charts
├── Cargo.toml
└── README.md
```

## Quick Start

```bash
# Build
cd contracts && forge install foundry-rs/forge-std --no-commit && forge build && cd ..
cargo build --release

# Test (18 Rust + 14 Foundry = 32 total)
cargo test --release
cd contracts && forge test -vv

# Benchmark (Classical vs Direct ML-KEM vs Pairwise)
cargo run -p bench --release

# Demo on Anvil
anvil &
cargo run -p demo --release
```

## Demo Output

```
================================================
  PQ Stealth Address — Demo
================================================

[setup] Sender:    0xf39F...
[setup] Recipient: 0x7099...

[contract] Deploying MemoRegistry...

--- SENDER: First Contact (Hybrid KEM) ---
  k_pairwise: a49fe28b...
  first contact gas: 78578

--- SENDER: Payment via Stealth Address ---
  stealth address: 0x8a5fd174...
  memo gas: 34206
  ETH transfer gas: 21000
  sent: 0.001 ETH

--- RECIPIENT: Scanning Memos ---
  derived stealth: 0x8a5fd174...
  ** PAYMENT FOUND: 0.001 ETH **
  recipient CAN sign from this address (has stealth_sk)
```

## Cryptographic Primitives

| Primitive | Purpose |
|-----------|---------|
| ML-KEM-768 (FIPS 203) | PQ key encapsulation (NIST Level 3) |
| ECDH (secp256k1) | Transitional hybrid security + stealth address derivation |
| HKDF-SHA256 | Hybrid KEM key combination, seed-to-key derivation |
| SHA-256 (domain-separated) | Pairwise stealth derivation, view tag computation |
| EC scalar addition | Viewing/spending separation (`stealth_sk = spending_sk + hash(ss)`) |

## Design Decisions

- **Gas as anti-spam**: MemoRegistry is a pure event log with no access control beyond gas cost. This matches ERC-5564's `ERC5564Announcer` design — anyone can post announcements. Scanning cost scales linearly with total announcements, bounded by chain gas limits.
- **No channel identifiers on memos**: Memos do not identify which pairwise channel they belong to. Adding a channel ID would improve scanning efficiency (skip non-matching channels) but would leak sender-recipient linkage on-chain. The current design uses view tags (1 byte, 99.6% filter rate) to reduce scanning cost without metadata leakage. For S senders × N memos, the recipient performs S × N view tag checks — each a single SHA-256 + byte comparison.
- **Sender visibility**: The sender's `msg.sender` is visible on every transaction — same as classical ERC-5564. Sender anonymity requires a relayer or account abstraction (ERC-4337).
- **Pairwise vs classical privacy**: In classical stealth (33 B/payment), all payments are identical-looking announcements. In pairwise (18 B/payment), `FirstContact` and `Memo` are distinguishable event types — an observer can count how many channels a sender has and how many total memos, though they can't link specific memos to specific channels (no channel ID). With multiple channels, the distribution is ambiguous. Stealth addresses are unique per payment in both models. The key tradeoff: if `k_pairwise` is compromised, all payments in that channel are linkable; in classical, each ephemeral key is independent. Pairwise does compartmentalize per-sender — one compromised `k_pairwise` reveals only one channel, while `viewing_dk` compromise reveals all.
- **Nonce reuse risk**: the pairwise derivation is deterministic in (k_pairwise, nonce). If a wallet reuses a nonce (state rollback, bad RNG), two payments land at the same stealth address — linking them on-chain. Wallet implementations should use a **monotonic counter** as the nonce, with on-chain recovery (count `Memo` events per channel). Tradeoff: counter leaks ordering; random nonces don't.
- **Demo is single-user**: The demo uses `.last()` for event queries, which is only correct for a single-user Anvil run. A production client must filter `KeyRegistered` by recipient address and try all `FirstContact` events via ML-KEM implicit rejection.

## What This PoC Does NOT Cover

- **PQ spending signatures**: Stealth addresses use secp256k1 ECDSA. Full PQ spending requires PQ signatures at the protocol level (EIP-7932). Our scope is PQ key exchange.
- **Token transfers**: Only demonstrates native ETH. ERC-20 transfers to stealth addresses work identically — the stealth address is a standard Ethereum address.
- **Sender privacy**: The sender's address is visible as `msg.sender` on MemoRegistry calls — same as classical ERC-5564. Stealth addresses protect recipient privacy, not sender privacy. Sender anonymity requires a relayer or account abstraction (ERC-4337).
- **On-chain key validation**: The contract validates key lengths but not cryptographic validity (e.g., valid secp256k1 point). Off-chain clients must re-validate keys from `KeyRegistered` events before use.

## Applicability to Aztec Note Discovery

Aztec's [note discovery](https://docs.aztec.network/developers/docs/foundational-topics/advanced/storage/note_discovery) system uses the same architecture: a shared secret (Grumpkin ECDH) produces tags for filtering, and recipients scan tagged notes. Aztec explicitly calls OMR a "long-term goal" that's "currently impractical."

| Aztec concept | pq_SA equivalent |
|---|---|
| Grumpkin ECDH shared secret | Hybrid KEM `k_pairwise` (PQ-secure) |
| Poseidon2 tag derivation | SHA-256 view tag (swappable) |
| "Can't receive from unknown sender" | First contact (non-interactive, same-block) |
| "OMR — currently impractical" | [pq_SA_OMR](https://github.com/namnc/pq_SA_OMR): Regev → Pasta (~128 B vs ~2 KB) |

What changes for Aztec: curve (secp256k1 → Grumpkin), hash (SHA-256 → Poseidon2), per-contract siloed tags. These are parameter choices — the hybrid KEM + EC scalar addition architecture is curve-agnostic.

## Related Work

- [Platus](https://docs.platus.xyz/architecture/quantum-security) — Hybrid KEM (Baby Jubjub + ML-KEM-1024) for encrypted notes. Same transitional security idea; uses NIST Level 5 (1,568 B ct) vs our Level 3 (1,088 B). SNARK-friendly curve. No pairwise channels or OMR.
- [ERC-5564](https://eips.ethereum.org/EIPS/eip-5564) — Stealth addresses (classical ECDH)
- [ERC-6538](https://eips.ethereum.org/EIPS/eip-6538) — Stealth meta-address registry
- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) — ML-KEM standard
- [BIP-47](https://github.com/bitcoin/bips/blob/master/bip-0047.mediawiki) — Reusable payment codes
- [Mikic et al. 2025](https://arxiv.org/html/2501.13733v1) — Lattice-based stealth addresses

## Acknowledgements

- Hy Ngo — Review and audit
- Vikas — Sepolia ETH for testnet deployment
- Keewoo Lee — Discussion on PQ privacy

## License

MIT
