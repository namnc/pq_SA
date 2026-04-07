# Post-Quantum Key Exchange for Stealth Addresses with Viewing/Spending Separation

We show how to add ML-KEM-768 to Ethereum stealth addresses (ERC-5564) via a **hybrid KEM** (ECDH + ML-KEM-768), preserving **viewing/spending key separation** via EC scalar addition. The hybrid provides transitional security: if either ECDH or ML-KEM holds, the shared secret is secure. A scanning server with the viewing key can detect payments but cannot spend. We also show a pairwise channel optimization that amortizes the 1,121 B hybrid ciphertext to a one-time cost.

**Code**: [github.com/namnc/pq_SA](https://github.com/namnc/pq_SA) (Rust + Solidity, 32 tests, Anvil demo)

## Motivation

ERC-5564 stealth addresses use ECDH for shared secret computation. A quantum computer breaks ECDH via Shor's algorithm. Privacy migration is more urgent than signature migration: signatures protect the future, but stealth address announcements already on-chain are vulnerable to harvest-now-decrypt-later (HNDL). An adversary recording today's ECDH ephemeral keys can break them later with a quantum computer, link all stealth addresses to recipients, and derive spending keys.

ML-KEM (FIPS 203) is the NIST-standardized post-quantum KEM. Replacing ECDH with ML-KEM for shared secret computation is straightforward — ML-KEM produces a shared secret just like ECDH, and the existing ERC-5564 stealth address derivation (EC scalar addition) works unchanged. The key is to preserve EC scalar addition for the stealth key derivation:

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

Server (with viewing_dk — safe to delegate):
  ss = ML-KEM-768.Decaps(viewing_dk, ct)
  check view_tag: hash(ss)[0] == tag?                    skip 99.6% of non-matches
  stealth_pk = spending_pk + hash(ss) * G
  check if address(stealth_pk) has balance               payment detected

Recipient (with spending_sk — never shared):
  stealth_sk = spending_sk + hash(ss)
  sign transaction from stealth address                  Ethereum-native auth
```

**Scanning is fast**: ML-KEM-768 decapsulation is ~36μs (measured, Apple Silicon). Scanning 10K announcements takes ~0.8s (direct) or ~0.4s (pairwise). View tags further reduce work by 99.6%.

### Pairwise Channel Optimization

The 1,088 B ciphertext per payment is the "PQ tax." For active sender-recipient pairs, a pairwise channel amortizes this to a one-time cost:

```
First contact (one-time):
  Hybrid KEM: ECDH(secp256k1) + ML-KEM-768 → k_pairwise    1,121 B

Per payment (after first contact):
  ss = SHA-256("pq-sa-pairwise-stealth-v1" || k_pairwise || nonce)
  stealth_pk = spending_pk + SHA-256("pq-sa-stealth-derive-v1" || ss) * G
  post memo(nonce, view_tag)                                 18 B on-chain
  send ETH to stealth address
```

The protocol is **non-interactive**: the sender only needs the recipient's public keys from the on-chain registry. First contact and first payment can happen in the same block — no round-trip. The recipient catches up later by scanning events.

The hybrid KEM provides transitional security: if either ECDH or ML-KEM holds, the pairwise key is secure.

**Privacy tradeoff vs classical**: In classical stealth (33 B/payment), all payments are identical-looking announcements. In pairwise (18 B/payment), `FirstContact` and `Memo` are distinguishable event types — an observer can count channels and total memos per sender, though they can't link specific memos to specific channels. The key tradeoff: if `k_pairwise` is compromised, all payments in that channel are linkable; in classical, each ephemeral key is independent. Pairwise compartmentalizes per-sender — one compromised `k_pairwise` reveals only one channel, while `viewing_dk` compromise reveals all.

**Harvest-now-decrypt-later defense**: A quantum attacker who records the first contact ciphertext today can later break the ECDH component via Shor's algorithm — but cannot break the ML-KEM-768 component. Since `k_pairwise = HKDF(ECDH_ss || ML-KEM_ss)`, both are required. All stealth addresses derived from `k_pairwise` remain hidden.

**Wallet recovery**: The recipient stores only a 32-byte seed. Keys are deterministic: `seed → (spending_sk, viewing_sk_ec, viewing_dk)`. First contact ciphertexts are permanently on-chain. To recover: re-derive keys from seed, scan `FirstContact` events, decapsulate each to get candidate `k_pairwise` values. Note: ML-KEM implicit rejection means decapsulation always returns a key, even for first contacts not addressed to you. Genuine channels are identified by checking view tags against `Memo` events — only matching channels produce consistent view tags. Work scales with total first contacts × memos; view tags (99.6% filter) keep verification fast.

**Hardware wallet integration**: The viewing/spending separation maps to hardware wallets: `spending_sk` stays on the hardware device, `viewing_dk` is exported to software wallets for scanning. A new phone recovers by getting `viewing_dk` from the hardware wallet and scanning on-chain events — zero state transfer. To spend, the software wallet sends `scalar = hash(shared_secret)` to the hardware wallet, which computes `stealth_sk = spending_sk + scalar` and signs.

### Measured (Anvil)

| | Classical ERC-5564 | Direct ML-KEM | Pairwise (this work) |
|--|-------------------|--------------|---------------------|
| PQ key exchange | No | **Yes** | **Yes** |
| Viewing/spending separation | Yes | **Yes** | **Yes** |
| View tag (99.6% filter) | Yes | **Yes** | **Yes** |
| Safe server delegation | Yes | **Yes** | **Yes** |
| Calldata per payment | 34 B | 1,089 B | **18 B** (after 1,121 B first contact) |
| Announcement gas | ~47K | ~61K | **~34K** (after ~79K first contact) |
| ETH transfer gas | 21K | 21K | 21K |
| Scanning 10K notes (measured) | ~0.7s | ~0.8s | ~0.4s |

## Why Pairwise Channels Were Not Adopted Classically

BIP-47 (2015) proposed pairwise payment codes for Bitcoin — saw limited adoption because the 33 B ECDH ephemeral key is trivial, and stealth addresses provide unlinkability without persistent state.

In PQ, the 1,088 B ML-KEM ciphertext makes pairwise channels an economically motivated optimization: 60x calldata reduction (1,089 → 18 B) for active channels. Not a necessity — the direct replacement works without it — but a significant saving.

## Scope and Limitations

- **PQ key exchange**: ML-KEM-768 (NIST Level 3). Quantum-secure.
- **Stealth address spending**: secp256k1 ECDSA. Quantum-vulnerable. Full PQ spending requires PQ transaction signatures at the Ethereum protocol level (EIP-7932). Our scope is the key exchange layer.
- **Stealth address lifespan**: recipients should sweep promptly to minimize the window for quantum attacks on the spending key.

## Implementation

32 tests (18 Rust + 14 Solidity). The PoC demonstrates:
- Hybrid KEM first contact → pairwise key establishment
- Stealth address derivation with viewing/spending separation
- Memo posting on MemoRegistry contract
- ETH transfer to stealth address
- Recipient scanning, detection, and spending verification

| Primitive | Purpose |
|-----------|---------|
| ML-KEM-768 (FIPS 203) | PQ key encapsulation |
| ECDH (secp256k1) | Transitional hybrid security + stealth derivation |
| EC scalar addition | Viewing/spending separation |
| HKDF-SHA256 | Hybrid KEM key combination, seed-to-key derivation |
| SHA-256 (domain-separated) | Pairwise stealth derivation, view tag computation |

## Applicability to Aztec Note Discovery

Aztec's [note discovery](https://docs.aztec.network/developers/docs/foundational-topics/advanced/storage/note_discovery) uses the same pattern: shared secret → tag derivation → scan. They identify OMR as a "long-term goal" that's "currently impractical." This work provides two applicable components:

1. **PQ shared secret** (pq_SA): replace Grumpkin ECDH with hybrid KEM. Tag derivation stays the same — just the shared secret source becomes PQ-secure. Non-interactive first contact solves Aztec's "can't receive from unknown sender" limitation.
2. **Practical OMR** ([pq_SA_OMR](https://github.com/namnc/pq_SA_OMR)): Regev → Pasta substitution reduces OMR signal from ~2 KB to 128 B. The curve (Grumpkin) and hash (Poseidon2) are parameter choices, not architectural constraints.

## Related Work

- [Platus](https://docs.platus.xyz/architecture/quantum-security) — Hybrid KEM (Baby Jubjub + ML-KEM-1024) for encrypted notes. Same transitional hybrid approach; NIST Level 5 (1,568 B ct). No pairwise channels or OMR.
- [ERC-5564](https://eips.ethereum.org/EIPS/eip-5564) — Stealth Addresses (classical ECDH)
- [ERC-6538](https://eips.ethereum.org/EIPS/eip-6538) — Stealth Meta-Address Registry
- [FIPS 203](https://csrc.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) — ML-KEM standard
- [Mikic et al. 2025](https://arxiv.org/html/2501.13733v1) — Lattice-based stealth address protocols (viewing key via lattice arithmetic, not Ethereum-compatible)
- [PQ Threats to Ethereum Privacy](https://ethresear.ch/t/post-quantum-threats-to-ethereum-privacy/24450) — namnc, ethresear.ch 2026
- [Towards Practical PQ Stealth Addresses](https://ethresear.ch/t/towards-practical-post-quantum-stealth-addresses/15437) — asanso, ethresear.ch 2023 (CSIDH-based)

## Acknowledgements

- Vikas — Sepolia ETH for testnet deployment
- Keewoo Lee — Discussion on PQ privacy
