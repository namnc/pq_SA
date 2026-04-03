# pq_SA

**Post-Quantum Key Exchange for Ethereum Stealth Addresses**

Replace ECDH with ML-KEM-768 in stealth addresses, preserving viewing/spending separation via EC scalar addition. Two models: direct ML-KEM (baseline) and pairwise channel (calldata optimization).

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
  stealth_pk = spending_pk + hash(HKDF(k_pairwise, nonce)) * G
  posts memo(nonce) on-chain                                ← 18 B
  sends ETH to address(stealth_pk)
```

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

| Transaction | Gas (measured) | Calldata |
|-------------|---------------|----------|
| Register keys (one-time) | 77,314 | 1,217 B (33 + 1,184) |
| First contact (one-time per pair) | 78,578 | 1,121 B |
| Memo (per payment) | 34,206 | 18 B |
| ETH transfer to stealth addr | 21,000 | 0 B |

ETH transfer is constant (21K gas) across all models. The announcement gas is what varies:

| Model | Announcement gas | Calldata |
|-------|-----------------|----------|
| Classical ERC-5564 | ~47K (estimated) | 34 B |
| Direct ML-KEM | ~61K (estimated) | 1,089 B |
| Pairwise (per payment) | **34,206 (measured)** | **18 B** |

## Project Structure

```
pq_SA/
├── contracts/
│   ├── src/MemoRegistry.sol       Stealth address discovery log (12 Foundry tests)
│   └── test/MemoRegistry.t.sol
├── crates/
│   ├── primitives/
│   │   ├── src/
│   │   │   ├── hybrid_kem.rs      ECDH + ML-KEM-768 hybrid KEM
│   │   │   └── stealth.rs         EC algebra stealth derivation (Model 1 + 2)
│   │   └── tests/e2e.rs           5 integration tests
│   ├── demo/                      Full Anvil demo (stealth address flow)
│   └── bench/                     Gas + CPU benchmarks, SVG charts
├── Cargo.toml
└── README.md
```

## Quick Start

```bash
# Build
cd contracts && forge build && cd ..
cargo build --release

# Test (17 Rust + 12 Foundry = 29 total)
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
| HKDF-SHA256 | Hybrid key derivation, pairwise stealth derivation |
| EC scalar addition | Viewing/spending separation (`stealth_sk = spending_sk + hash(ss)`) |

## What This PoC Does NOT Cover

- **PQ spending signatures**: Stealth addresses use secp256k1 ECDSA. Full PQ spending requires PQ signatures at the protocol level (EIP-7932). Our scope is PQ key exchange.
- **Token transfers**: Only demonstrates native ETH. ERC-20 transfers to stealth addresses work identically — the stealth address is a standard Ethereum address.
- **Sender privacy**: The sender's address is visible as `msg.sender` on MemoRegistry calls. Sender anonymity requires a relayer or account abstraction layer.

## Related Work

- [ERC-5564](https://eips.ethereum.org/EIPS/eip-5564) — Stealth addresses (classical ECDH)
- [ERC-6538](https://eips.ethereum.org/EIPS/eip-6538) — Stealth meta-address registry
- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) — ML-KEM standard
- [BIP-47](https://github.com/bitcoin/bips/blob/master/bip-0047.mediawiki) — Reusable payment codes
- [Mikic et al. 2025](https://arxiv.org/html/2501.13733v1) — Lattice-based stealth addresses

## Acknowledgements

- Vikas — Sepolia ETH for testnet deployment
- Keewoo Lee — Discussion on PQ privacy

## License

MIT
