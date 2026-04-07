# Post-Quantum Key Exchange for Stealth Addresses with Viewing/Spending Separation

We show how to add ML-KEM-768 ([FIPS 203](https://csrc.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)) to Ethereum stealth addresses (ERC-5564) via a **hybrid KEM** (ECDH + ML-KEM-768), preserving **viewing/spending key separation** via EC scalar addition. The hybrid provides transitional security: if either ECDH or ML-KEM holds, the shared secret is secure. A scanning server with the viewing bundle can detect payments but cannot spend. We also show a pairwise channel optimization that amortizes the 1,121 B hybrid ciphertext (33 B ECDH ephemeral key + 1,088 B ML-KEM ciphertext) to a one-time cost.

**Code**: [github.com/namnc/pq_SA](https://github.com/namnc/pq_SA) (Rust + Solidity, 33 tests, Anvil demo)
**Quick start**: `cd contracts && forge install foundry-rs/forge-std --no-commit && forge build && cd .. && cargo test --release`

## Motivation

ERC-5564 stealth addresses use ECDH for shared secret computation. A quantum computer breaks ECDH via Shor's algorithm. Privacy migration is more urgent than signature migration: signatures protect the future, but stealth address announcements already on-chain are vulnerable to harvest-now-decrypt-later (HNDL). An adversary recording today's ECDH ephemeral keys can break them later with a quantum computer, link all stealth addresses to recipients, and derive spending keys.

ML-KEM (FIPS 203) is the NIST-standardized post-quantum KEM. Replacing ECDH with ML-KEM for shared secret computation is straightforward — ML-KEM produces a shared secret just like ECDH, and the existing ERC-5564 stealth address derivation (EC scalar addition) works unchanged.

## Notation

| Symbol | Meaning |
|--------|---------|
| `ss_ec` | ECDH shared secret (x-coordinate of ECDH point) |
| `ss_kem` | ML-KEM-768 shared secret (32 B) |
| `k_pairwise` | Combined pairwise key: `HKDF(ss_ec \|\| ss_kem \|\| epk)` |
| `spending_sk/pk` | secp256k1 keypair for stealth key derivation (NEVER delegated) |
| `viewing_sk_ec` | EC secret key for ECDH in hybrid KEM (safe to delegate) |
| `dk_kem / ek_kem` | ML-KEM-768 decapsulation/encapsulation key (safe to delegate) |
| Viewing bundle | `(viewing_sk_ec, dk_kem)` — both needed to recover `k_pairwise` |

## EC Scalar Addition (same as ERC-5564)

```
stealth_pk = spending_pk + hash(shared_secret) * G     ← public (anyone with ss can compute)
stealth_sk = spending_sk + hash(shared_secret)          ← private (needs spending_sk)
```

The viewing key holder knows `hash(shared_secret)` and `spending_pk` (public) — enough to derive `stealth_pk` for payment detection. But computing `stealth_sk` requires `spending_sk`, which the server never sees. This is exactly how classical ERC-5564 works — we just change the shared secret source from ECDH to ML-KEM.

## Protocol

### Direct ML-KEM Stealth (drop-in ERC-5564 replacement)

```
Recipient publishes:
  spending_pk   (secp256k1, 33 B)
  viewing_ek    (ML-KEM-768, 1,184 B)

Sender (per payment):
  (ct, ss) = ML-KEM-768.Encaps(viewing_ek)              1,088 B ciphertext
  stealth_pk = spending_pk + hash(ss) * G
  view_tag = hash(ss)[0]                                 1 B (filters 99.6%)
  post announcement: ct + view_tag                       1,089 B on-chain
  send ETH to address(stealth_pk)

Server (with viewing bundle — safe to delegate):
  ss = ML-KEM-768.Decaps(viewing_dk, ct)
  check view_tag: hash(ss)[0] == tag?                    skip 99.6% of non-matches
  stealth_pk = spending_pk + hash(ss) * G
  check if address(stealth_pk) has balance               payment detected

Recipient (with spending_sk — never shared):
  stealth_sk = spending_sk + hash(ss)
  sign transaction from stealth address                  Ethereum-native auth
```

**Scanning is fast**: ML-KEM-768 decapsulation is ~36μs (measured, Apple M-series, Rust). Full per-memo scan cost includes decapsulation + SHA-256 hash + view tag check + EC point addition for stealth derivation ≈ 77μs/memo (direct) or 40μs/memo (pairwise, HKDF only). Scanning 10K announcements takes ~0.8s (direct) or ~0.4s (pairwise). In production, event log fetching and RPC latency will dominate over crypto cost. View tags filter `1 - 1/256 = 99.6%` of non-matches (1 byte → 256 possible values → 0.39% false positive rate per memo). A malicious sender flooding with matching view tags would increase scan work but not break correctness — the stealth address derivation + balance check is the final filter.

### Pairwise Channel Optimization

The 1,088 B ciphertext per payment is the "PQ tax." For active sender-recipient pairs, a pairwise channel amortizes this to a one-time cost:

```
First contact (one-time):
  Hybrid KEM: ECDH(secp256k1) + ML-KEM-768 → k_pairwise
  On-chain: 1,121 B (33 B ECDH ephemeral key + 1,088 B ML-KEM ciphertext)

Per payment (after first contact):
  ss = SHA-256("pq-sa-pairwise-stealth-v1" || k_pairwise || nonce)
  stealth_pk = spending_pk + SHA-256("pq-sa-stealth-derive-v1" || ss) * G
  post memo(nonce, view_tag)                                 17 B payload on-chain
  send ETH to stealth address
```

The protocol is **non-interactive**: the sender only needs the recipient's public keys from the on-chain registry. First contact and first payment can happen in the same block — no round-trip. The recipient catches up later by scanning events.

```
Sender                          On-chain                    Recipient/Server
  │                                │                              │
  ├─ postFirstContact(epk+ct) ───>│ FirstContact event           │
  ├─ postMemo(nonce, viewTag) ───>│ Memo event                   │
  ├─ ETH transfer ───────────────>│ stealth_addr receives ETH    │
  │                                │                              │
  │                                │<── scan FirstContact ────────┤
  │                                │    decapsulate → k_pairwise  │
  │                                │<── scan Memo ────────────────┤
  │                                │    check viewTag (99.6% filter)
  │                                │    derive stealth_addr       │
  │                                │    check balance → FOUND     │
```

The hybrid KEM provides transitional security: if either ECDH or ML-KEM holds, the pairwise key is secure. The KDF binds the full ephemeral key (including parity byte) to prevent replay: `k_pairwise = HKDF(ECDH_ss || ML-KEM_ss || epk, "pq-sa-v1")`.

**Nonce handling**: each memo uses a random 16-byte nonce (128-bit collision resistance — negligible collision probability at 2^64 nonces). The nonce is posted on-chain and used as input to the domain-separated SHA-256 derivation. Replay protection: the same (k_pairwise, nonce) pair always produces the same stealth address, so a replayed memo just re-derives the same address — no new funds are at risk. The nonce should be unique per payment to avoid address reuse, which would aid traffic analysis (an observer could correlate transactions to the same address).

### Privacy Tradeoff vs Classical

In classical stealth (33 B/payment), all payments are identical-looking announcements. In pairwise (17 B/payment), `FirstContact` and `Memo` are distinguishable event types — an observer can count channels and total memos per sender, though they can't link specific memos to specific channels (no channel ID). With multiple channels, the distribution is ambiguous. The key tradeoff: if `k_pairwise` is compromised, all payments in that channel are linkable; in classical, each ephemeral key is independent. Pairwise compartmentalizes per-sender — one compromised `k_pairwise` reveals only one channel, while `viewing_dk` compromise reveals all.

Mitigation for channel-count leakage: senders can post **dummy first contacts** (encrypted to random keys) to obscure the true number of active channels. Cost: one additional 1,121 B event per dummy channel.

**Archival note**: first-contact ciphertexts are event calldata — cheap to post (~0.0005 ETH at 30 gwei) but must be retained by archival nodes for wallet recovery. Long-term, a Merkle commitment over first contacts could compress the archival burden while preserving verifiability.

### Security Properties

The hybrid KEM construction provides the following properties (informal):

- **IND-CCA security of ML-KEM-768**: the ML-KEM ciphertext is indistinguishable from random under chosen-ciphertext attack (NIST Level 3, ~128-bit PQ security).
- **GDH security of secp256k1**: the ECDH shared secret is secure under the Gap Diffie-Hellman assumption (classical security).
- **Transitional ("either-or") security**: `k_pairwise = HKDF(ECDH_ss || ML-KEM_ss || epk)`. An adversary must break **both** ML-KEM and ECDH to recover `k_pairwise`. HKDF is modeled as a random oracle.
- **Stealth address unlinkability**: given `stealth_pk = spending_pk + hash(k_pairwise, nonce) * G`, an observer without `k_pairwise` cannot link the stealth address to the recipient (reduces to the decisional Diffie-Hellman problem on the stealth derivation curve).
- **Viewing/spending separation**: the viewing bundle (`viewing_sk_ec` + `dk_kem`) can detect payments but cannot compute `stealth_sk = spending_sk + hash(ss)` without `spending_sk`. This is identical to ERC-5564's security model.
- **Explicit reduction**: `Pr[adversary recovers k_pairwise] ≤ Pr[break GDH on secp256k1] + Pr[break IND-CCA of ML-KEM-768]`. Both must fail for compromise (follows from the hybrid-crypto composition theorem, cf. Bellare-Rogaway 2000).
- **Key-compromise impersonation (KCI)**: a compromised viewing bundle enables an attacker to **detect** all future payments to that recipient (but not spend). This aligns with ERC-5564's threat model. Mitigation: rotate viewing keys by re-registering; old first contacts remain decryptable from the seed.
- **Side channels**: ML-KEM decapsulation should be constant-time. The `ml-kem` Rust crate implements constant-time decapsulation. Server-side scanning should use constant-time comparison for view tags to avoid timing leakage.

### HNDL Defense

A quantum attacker who records the first contact ciphertext today can later break the ECDH component via Shor's algorithm — but cannot break the ML-KEM-768 component. Since `k_pairwise = HKDF(ECDH_ss || ML-KEM_ss || epk)`, both are required. All stealth addresses derived from `k_pairwise` remain hidden.

### Wallet Recovery

The recipient stores only a 32-byte seed. Keys are derived deterministically via labeled HKDF: `spending_sk = HKDF(seed, "pq-sa-spending-v1")`, `viewing_sk_ec = HKDF(seed, "pq-sa-viewing-ec-v1")`, `ml_kem_seed = HKDF(seed, "pq-sa-viewing-kem-v1")`. First contact ciphertexts are permanently on-chain. To recover: re-derive keys from seed, scan `FirstContact` events, decapsulate each to get candidate `k_pairwise` values. Note: ML-KEM implicit rejection means decapsulation always returns a key, even for first contacts not addressed to you. Genuine channels are identified by checking view tags against `Memo` events — only matching channels produce consistent view tags.

### Hardware Wallet Integration

The viewing/spending separation maps to hardware wallets: `spending_sk` stays on the hardware device, the viewing bundle (`viewing_sk_ec` + `dk_kem`) is exported to software wallets for scanning. Both secrets in the viewing bundle are needed to recover `k_pairwise` from first contacts. To spend, the software wallet sends `scalar = hash(shared_secret)` to the hardware wallet, which computes `stealth_sk = spending_sk + scalar` and signs.

### Measured (Anvil, Apple M-series)

| | Classical ERC-5564 | Direct ML-KEM | Pairwise (this work) |
|--|-------------------|--------------|---------------------|
| PQ key exchange | No | **Yes** | **Yes** |
| Viewing/spending separation | Yes | **Yes** | **Yes** |
| View tag (99.6% filter) | Yes | **Yes** | **Yes** |
| Safe server delegation | Yes | **Yes** | **Yes** |
| Payload per payment | 34 B | 1,089 B | **17 B** (after 1,121 B first contact) |
| Announcement gas | ~47K | ~61K | **~34K** (after ~79K first contact) |
| ETH transfer gas | 21K | 21K | 21K |
| Scanning 10K notes | ~0.7s | ~0.8s | ~0.4s |

Payload sizes are application data, not ABI-encoded wire calldata. Gas numbers are measured on Anvil and include ABI overhead.

**10-payment channel comparison** (total gas for 10 payments to the same recipient):

| Model | Total gas | Total payload |
|-------|-----------|---------------|
| Classical (10 × announce + ETH) | ~680K | 340 B |
| Direct ML-KEM (10 × announce + ETH) | ~820K | 10,890 B |
| **Pairwise (1 first contact + 10 memos + ETH)** | **~499K** | **1,291 B** |

Pairwise breaks even with classical after ~3 payments and saves ~39% gas over direct ML-KEM for a 10-payment channel.

**On-chain storage cost**: the 1,121 B first-contact ciphertext is stored as event calldata (not state), so it does not occupy persistent storage. At 16 gas/nonzero-byte and 30 gwei gas price, a first contact costs ~0.0005 ETH in calldata gas.

## Migration Path

A recipient can register both classical (ERC-5564 ECDH) and PQ (hybrid KEM) meta-addresses simultaneously. The registry stores both; legacy senders use the ECDH key, newer senders use the hybrid KEM. Over time, the ecosystem migrates. Key rotation: the recipient re-registers with new viewing keys; old first contacts remain decryptable with the old keys (which the seed can re-derive). Revocation is implicit — a new registration supersedes the old one.

## Why Pairwise Channels Were Not Adopted Classically

BIP-47 (2015) proposed pairwise payment codes for Bitcoin — saw limited adoption because the 33 B ECDH ephemeral key is trivial, and stealth addresses provide unlinkability without persistent state.

In PQ, the 1,088 B ML-KEM ciphertext makes pairwise channels an economically motivated optimization: ~60x payload reduction (1,089 → 17 B) for active channels. Not a necessity — the direct replacement works without it — but a significant saving at ~16 gas/byte.

## Scope and Limitations

- **PQ key exchange**: ML-KEM-768 (NIST Level 3). Quantum-secure.
- **Stealth address spending**: secp256k1 ECDSA. Quantum-vulnerable. Full PQ spending requires PQ transaction signatures at the Ethereum protocol level (EIP-7932). Our scope is the key exchange layer — composable with future PQ signature schemes.
- **Stealth address lifespan**: recipients should sweep promptly to minimize the window for quantum attacks on the spending key.
- **Dependency**: `ml-kem = 0.3.0-rc.1` (pre-release, unaudited). Experimental research PoC.

## Implementation

33 tests (19 Rust + 14 Solidity). The PoC demonstrates:
- Hybrid KEM first contact → pairwise key establishment
- Stealth address derivation with viewing/spending separation
- Memo posting on MemoRegistry contract
- ETH transfer to stealth address
- Recipient scanning, detection, and spending verification
- Type-safe key separation: `ViewingKeys` vs `SpendingKey`

| Primitive | Purpose |
|-----------|---------|
| [ML-KEM-768](https://csrc.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) (FIPS 203) | PQ key encapsulation (NIST Level 3, 1,088 B ct, 32 B ss) |
| ECDH (secp256k1) | Transitional hybrid security + stealth derivation |
| EC scalar addition | Viewing/spending separation |
| HKDF-SHA256 | Hybrid KEM key combination, seed-to-key derivation |
| SHA-256 (domain-separated) | Pairwise stealth derivation, view tag computation |

## Comparison with Related Work

| | Classical ERC-5564 | Mikic et al. 2025 | Platus | **This work** |
|--|---|---|---|---|
| Key exchange | ECDH | Lattice-only | BJJ + ML-KEM-1024 | **ECDH + ML-KEM-768** |
| PQ security | No | Yes | Yes (Level 5) | **Yes (Level 3)** |
| Viewing/spending separation | Yes | Lattice arithmetic | Separate vk/mSK | **EC scalar addition** |
| Ethereum-compatible | Yes | No | SNARK-friendly | **Yes (secp256k1)** |
| Pairwise channels | No | No | No | **Yes (17 B/payment)** |
| Hybrid (transitional) | — | No | Yes | **Yes** |
| OMR support | No | No | No | **Yes** ([pq_SA_OMR](https://github.com/namnc/pq_SA_OMR)) |

## Applicability to Aztec Note Discovery

Aztec's [note discovery](https://docs.aztec.network/developers/docs/foundational-topics/advanced/storage/note_discovery) uses the same pattern: shared secret → tag derivation → scan. They identify OMR as a "long-term goal" that's "currently impractical." This work provides two applicable components:

1. **PQ shared secret** (pq_SA): replace Grumpkin ECDH with hybrid KEM. Tag derivation stays the same — just the shared secret source becomes PQ-secure. Non-interactive first contact solves Aztec's "can't receive from unknown sender" limitation.
2. **Practical OMR** ([pq_SA_OMR](https://github.com/namnc/pq_SA_OMR)): Regev → Pasta substitution reduces OMR signal from ~2 KB to 128 B. The curve (Grumpkin) and hash (Poseidon2) are parameter choices, not architectural constraints.

## Future Work

- **Full PQ spending**: integrating PQ signature schemes (Dilithium, Falcon) via EIP-7932 would close the remaining quantum gap. The key-exchange layer (this work) is composable with any future PQ transaction-signature scheme.
- **ML-KEM-1024**: Level 5 security at 1,568 B ciphertext — the pairwise optimization becomes even more valuable (1,568 B amortized to 17 B).
- **Cross-chain**: L2s (Arbitrum, Optimism) already adopt ERC-5564. The pairwise approach works identically; only calldata pricing differs.
- **Privacy-enhanced view tags**: PRF-derived tags (instead of hash truncation) could reduce metadata leakage from tag collisions. Optional 2-byte tags for high-volume services would reduce false positives to 0.0015%.
- **Threshold viewing**: `t-of-n` viewing key sharing for multi-party compliance (e.g., custodial services that require multiple parties to detect payments).

## Related Work

- [Platus](https://docs.platus.xyz/architecture/quantum-security) — Hybrid KEM (Baby Jubjub + ML-KEM-1024) for encrypted notes. NIST Level 5. No pairwise channels or OMR.
- [ERC-5564](https://eips.ethereum.org/EIPS/eip-5564) — Stealth Addresses (classical ECDH)
- [ERC-6538](https://eips.ethereum.org/EIPS/eip-6538) — Stealth Meta-Address Registry
- [FIPS 203](https://csrc.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) — ML-KEM standard
- [Mikic et al. 2025](https://arxiv.org/html/2501.13733v1) — Lattice-based stealth address protocols (viewing key via lattice arithmetic, not Ethereum-compatible)
- [PQ Threats to Ethereum Privacy](https://ethresear.ch/t/post-quantum-threats-to-ethereum-privacy/24450) — namnc, ethresear.ch 2026
- [Towards Practical PQ Stealth Addresses](https://ethresear.ch/t/towards-practical-post-quantum-stealth-addresses/15437) — asanso, ethresear.ch 2023 (CSIDH-based)
- [BIP-47](https://github.com/bitcoin/bips/blob/master/bip-0047.mediawiki) — Reusable payment codes (classical pairwise channels)
- [NIST SP 800-208](https://csrc.nist.gov/publications/detail/sp/800-208/final) — Recommendation for stateful hash-based signature schemes (context for hybrid approaches)

## Acknowledgements

- Vikas — Sepolia ETH for testnet deployment
- Keewoo Lee — Discussion on PQ privacy
