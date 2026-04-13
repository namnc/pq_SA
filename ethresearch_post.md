# Post-Quantum Key Exchange for Stealth Addresses with Viewing/Spending Separation

We show how to add ML-KEM-768 ([FIPS 203](https://csrc.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)) to Ethereum stealth addresses (ERC-5564) via a **hybrid KEM** (ECDH + ML-KEM-768), preserving **viewing/spending key separation** via EC scalar addition. The hybrid provides transitional security: if either ECDH or ML-KEM holds, the shared secret is secure. A scanning server with the viewing bundle can detect payments but cannot spend. We also show a pairwise channel optimization that amortizes the 1,121 B hybrid ciphertext (33 B ECDH ephemeral key + 1,088 B ML-KEM ciphertext) to a one-time cost.

**Code**: [github.com/namnc/pq_SA](https://github.com/namnc/pq_SA) (Rust + Solidity, 33 tests, Anvil demo)
**Quick start**: `cd contracts && forge install foundry-rs/forge-std --no-commit && forge build && cd .. && cargo test --release`

## Motivation

ERC-5564 stealth addresses use ECDH for shared secret computation. A quantum computer breaks ECDH via Shor's algorithm. Recent developments compress the timeline: Google's 2026 research shows [~25,000 physical qubits may suffice](https://scottaaronson.blog/?p=8669) to break 256-bit elliptic curves (including secp256k1) — down from millions previously estimated. Scott Aaronson: *"maybe a year saved"* on CRQC, *"people should really get on upgrading to quantum-resistant cryptography."* [Oratomic's paper](https://words.filippo.io/crqc-timeline/) shows ~10,000 physical qubits with neutral-atom architectures. Filippo Valsorda (Go crypto lead) now sets a **2029 deadline**: *"the bet is not 'are you 100% sure a CRQC will exist in 2030?', the bet is 'are you 100% sure a CRQC will NOT exist in 2030?'"*

Privacy migration is more urgent than signature migration: signatures protect the future, but stealth address announcements **already on-chain** are vulnerable to harvest-now-decrypt-later (HNDL). Every ECDH ephemeral key posted today is a commitment that becomes breakable if a CRQC arrives. The migration window may be as short as 33 months.

ML-KEM ([FIPS 203](https://csrc.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)) is the NIST-standardized post-quantum KEM. Replacing ECDH with ML-KEM for shared secret computation is straightforward — ML-KEM produces a shared secret just like ECDH, and the existing ERC-5564 stealth address derivation (EC scalar addition) works unchanged. Valsorda recommends "ML-KEM for key exchange (hybrid acceptable during transition)" — exactly our approach.

## Notation

| Symbol | Meaning |
|--------|---------|
| `ss_ec` | ECDH shared secret (x-coordinate of ECDH point) |
| `ss_kem` | ML-KEM-768 shared secret (32 B) |
| `k_pairwise` | Combined pairwise key: `HKDF(ss_ec \|\| ss_kem \|\| epk, "pq-sa-v1")` |
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
  ek_kem        (ML-KEM-768, 1,184 B)

Sender (per payment):
  (ct, ss) = ML-KEM-768.Encaps(ek_kem)                   1,088 B ciphertext
  stealth_pk = spending_pk + hash(ss) * G
  view_tag = hash(ss)[0]                                 1 B (filters 99.6%)
  post announcement: ct + view_tag                       1,089 B on-chain
  send ETH to address(stealth_pk)

Server (with dk_kem — safe to delegate):
  ss = ML-KEM-768.Decaps(dk_kem, ct)
  check view_tag: hash(ss)[0] == tag?                    skip 99.6% of non-matches
  stealth_pk = spending_pk + hash(ss) * G
  check if address(stealth_pk) has balance               payment detected

Recipient (with spending_sk — never shared):
  stealth_sk = spending_sk + hash(ss)
  sign transaction from stealth address                  Ethereum-native auth
```

In the pseudocode above, `hash(ss)` abbreviates domain-separated SHA-256. The actual view tag computation is `SHA-256("pq-sa-view-tag-v1" || ss)[0]`; stealth offset is `SHA-256("pq-sa-stealth-derive-v1" || ss)`.

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

The hybrid KEM provides transitional security: if either ECDH or ML-KEM holds, the pairwise key is secure. The KDF binds the full ephemeral key (including parity byte) to prevent replay: `k_pairwise = HKDF(ss_ec || ss_kem || epk, "pq-sa-v1")`.

**Nonce handling**: each memo uses a 16-byte nonce (128 bits). The birthday bound gives collision probability ~k²/2^{129} for k random nonces per channel — negligible for realistic payment counts (at k = 2^{32}, probability is ~2^{-65}). The nonce is posted on-chain and used as input to the domain-separated SHA-256 derivation. Replay protection: the same (k_pairwise, nonce) pair always produces the same stealth address — no new funds are at risk from replay. The nonce **must** be unique per payment: reuse produces the same stealth address, linking two payments on-chain and breaking privacy for that pair.

Wallet implementations should use a **monotonic counter** (not random) as the nonce to prevent reuse from state rollback, backup restore, or bad RNG. On recovery, the wallet derives the next safe counter from the number of `Memo` events found on-chain for that channel. Tradeoff: a counter leaks payment ordering (observer knows which memo is newer); random nonces don't. The protocol is agnostic — works with either approach.

### Privacy Tradeoff vs Classical

In classical stealth (33 B/payment), all payments are identical-looking announcements. In pairwise (17 B/payment), `FirstContact` and `Memo` are distinguishable event types — an observer can count channels and total memos per sender, though they can't link specific memos to specific channels (no channel ID). With multiple channels, the distribution is ambiguous. The key tradeoff: if `k_pairwise` is compromised, all payments in that channel are linkable; in classical, each ephemeral key is independent. Pairwise compartmentalizes per-sender — one compromised `k_pairwise` reveals only one channel, while viewing bundle compromise reveals all.

Mitigation for channel-count leakage: senders can post **dummy first contacts** (encrypted to random keys) to obscure the true number of active channels. Cost: one additional 1,121 B event per dummy channel.

**Archival note**: first-contact ciphertexts are event calldata — cheap to post (~0.0024 ETH total transaction gas at 30 gwei, of which ~0.0005 ETH is calldata) but must be retained by archival nodes for wallet recovery. Long-term, a Merkle commitment over first contacts could compress the archival burden while preserving verifiability.

### Forward Secrecy and Nonce Management

The pairwise model introduces two limitations absent in both classical stealth addresses and direct ML-KEM: (1) per-receiver nonce state and (2) no per-payment forward secrecy. These are not implementation gaps — they are inherent to **any scheme that reuses a shared secret across payments**, which is what the pairwise optimization does.

**Neither classical nor direct ML-KEM has these problems.** In classical ERC-5564, the sender generates a fresh ephemeral keypair per payment from the OS CSPRNG — no nonce, no per-receiver state, no long-lived shared secret. Direct ML-KEM (Model 1) works the same way: fresh encapsulation per payment, internal randomness, stateless. Standard wallet practice (Umbra, etc.) is: call the CSPRNG, compute the ECDH/KEM, post, forget. Birthday collision on a 256-bit random scalar or ML-KEM internal randomness requires ~2^{128} payments — not a concern.

The pairwise model trades this statelessness for 64× smaller per-payment calldata. The nonce is the pairwise model's substitute for the fresh randomness that classical and direct models get for free from ephemeral key generation. The static `k_pairwise` is what eliminates per-payment forward secrecy. Both problems are the cost of amortization — not of post-quantum cryptography itself.

**The constraint.** No known PQ KEM produces ciphertexts under ~700 bytes. ECDH ephemeral keys are 33 bytes; ML-KEM-768 ciphertexts are 1,088 bytes. This 33× gap makes per-payment PQ encapsulation expensive, motivating the pairwise optimization. But the optimization introduces a long-lived shared secret (`k_pairwise`), which creates both problems: nonces are needed to differentiate payments under the same key, and the static key means compromise reveals the entire channel history (nonces are on-chain in plaintext).

**The trilemma.** A stealth address scheme cannot simultaneously achieve all three:

1. Post-quantum per-payment security
2. Per-payment forward secrecy (and stateless nonce management)
3. Small per-payment calldata (< ~50 B)

Classical ERC-5564 achieves (2) + (3): a fresh 33-byte ephemeral key per payment, independent forward secrecy, no shared state. Pairwise PQ achieves (1) + (3): 17-byte memos after a one-time first contact. Direct ML-KEM achieves (1) + (2): fresh encapsulation per payment, stateless — but 1,088 bytes each.

**Approaches considered and rejected** (for recovering forward secrecy within the pairwise model):

| Approach | What it gives | Why it fails |
|---|---|---|
| **Hash chain ratchet** `k_{i+1} = H(k_i \|\| i)` | Sender-side forward secrecy after deletion of `k_i` | Requires ordered processing; blockchain scanning is unordered. Receiver must walk the chain sequentially to reach memo `i`. |
| **GGM tree (puncturable PRF)** | Per-payment forward secrecy + random access via tree-path derivation; sender/server puncture used leaves | 32 hashes per derivation, complex puncture state (≤1 KB/channel), and the receiver can always reconstruct from seed — bounding forward secrecy to the hot scanning key, not the cold recovery path. |
| **Per-payment ephemeral EC** `HKDF(ECDH(esk, viewing_pk_ec) \|\| k_pairwise)` | Classical forward secrecy; eliminates nonce management (epk is stateless) | 34 B/payment (2× current). No PQ forward secrecy — Shor's algorithm recovers `ss_ec` from on-chain `epk`, leaving only `k_pairwise` as protection, which is the static-key problem restated. |
| **Periodic re-keying** (new first contact every N payments) | Epoch-bounded forward secrecy | 1,121 B per re-key; forward secrecy is epoch-granular, not per-payment. Doesn't solve nonce management within an epoch. |

All four fail for the same root cause: **per-payment PQ forward secrecy requires per-payment PQ key encapsulation** (1,088 B), which is precisely what the pairwise optimization exists to avoid. Nonce management is similarly inherent: any scheme that reuses a shared secret needs a differentiator, and that differentiator requires per-receiver state.

**What the pairwise model does provide:**
- **HNDL defense**: a quantum attacker who records today's first contact ciphertext cannot recover `k_pairwise` (ML-KEM-768 protects the first contact).
- **Channel compartmentalization**: compromise of one `k_pairwise` reveals only that channel.
- **Spending safety**: `k_pairwise` compromise enables payment detection but never spending (`spending_sk` is never derived from the viewing bundle).
- **Stateless fallback**: wallets that prioritize forward secrecy and stateless operation over calldata efficiency can use direct ML-KEM (1,089 B/payment, no nonce, no `k_pairwise`) — this is the alternative described in [Direct ML-KEM as Default](#direct-ml-kem-as-default). The choice between pairwise and direct is a per-wallet policy decision, not a protocol constraint.

### Security Properties

The hybrid KEM construction provides the following properties (informal):

- **IND-CCA security of ML-KEM-768**: the ML-KEM ciphertext is indistinguishable from random under chosen-ciphertext attack (NIST Level 3, ~128-bit PQ security).
- **GDH security of secp256k1**: the ECDH shared secret is secure under the Gap Diffie-Hellman assumption (classical security).
- **Transitional ("either-or") security**: `k_pairwise = HKDF(ss_ec || ss_kem || epk, "pq-sa-v1")`. An adversary must break **both** ML-KEM and ECDH to recover `k_pairwise`. HKDF is modeled as a random oracle.
- **Stealth address unlinkability**: given `stealth_pk = spending_pk + hash(k_pairwise, nonce) * G`, an observer without `k_pairwise` cannot link the stealth address to the recipient (reduces to the decisional Diffie-Hellman problem on the stealth derivation curve).
- **Viewing/spending separation**: the viewing bundle (`viewing_sk_ec` + `dk_kem`) can detect payments but cannot compute `stealth_sk = spending_sk + hash(ss)` without `spending_sk`. This is identical to ERC-5564's security model.
- **Explicit reduction**: `Pr[adversary recovers k_pairwise] ≤ Pr[break GDH on secp256k1] + Pr[break IND-CCA of ML-KEM-768]`. The adversary must break both for compromise (union bound; follows from the hybrid-crypto composition theorem, cf. Bellare-Rogaway 2000).
- **Key-compromise impersonation (KCI)**: a compromised viewing bundle enables an attacker to **detect** all future payments to that recipient (but not spend). This aligns with ERC-5564's threat model. Mitigation: rotate viewing keys by re-registering; old first contacts remain decryptable from the seed.
- **Side channels**: ML-KEM decapsulation should be constant-time. The `ml-kem` Rust crate implements constant-time decapsulation. Server-side scanning should use constant-time comparison for view tags to avoid timing leakage.

### HNDL Defense

A quantum attacker who records the first contact ciphertext today can later break the ECDH component via Shor's algorithm — but cannot break the ML-KEM-768 component. Since `k_pairwise = HKDF(ss_ec || ss_kem || epk, "pq-sa-v1")`, both shared secrets are required. All stealth addresses derived from `k_pairwise` remain hidden.

### Wallet Recovery

The recipient stores only a 32-byte seed. Keys are derived deterministically via labeled HKDF: `spending_sk = HKDF(seed, "pq-sa-spending-v1")`, `viewing_sk_ec = HKDF(seed, "pq-sa-viewing-ec-v1")`, `ml_kem_seed = HKDF(seed, "pq-sa-viewing-kem-v1")`. First contact ciphertexts are permanently on-chain. To recover: re-derive keys from seed, scan `FirstContact` events, decapsulate each to get candidate `k_pairwise` values. Note: ML-KEM implicit rejection means decapsulation always returns a key, even for first contacts not addressed to you. Genuine channels are identified by checking view tags against `Memo` events — only matching channels produce consistent view tags.

### Hardware Wallet Integration

The viewing/spending separation maps to hardware wallets: `spending_sk` stays on the hardware device, the viewing bundle (`viewing_sk_ec` + `dk_kem`) is exported to software wallets for scanning. Both secrets in the viewing bundle are needed to recover `k_pairwise` from first contacts. To spend, the software wallet sends `scalar = hash(shared_secret)` to the hardware wallet, which computes `stealth_sk = spending_sk + scalar` and signs.

### Gas and Performance

| | Classical ERC-5564 | Direct ML-KEM | Pairwise (this work) |
|--|-------------------|--------------|---------------------|
| PQ key exchange | No | **Yes** | **Yes** |
| Viewing/spending separation | Yes | **Yes** | **Yes** |
| View tag (99.6% filter) | Yes | **Yes** | **Yes** |
| Safe server delegation | Yes | **Yes** | **Yes** |
| Payload per payment | 34 B | 1,089 B | **17 B** (after 1,121 B first contact) |
| Announcement gas | ~47K (estimated) | ~64K (estimated) | **~34K (measured)** (after ~79K first contact) |
| ETH transfer gas | 21K | 21K | 21K |
| Scanning 10K notes (measured) | ~0.7s | ~0.8s | ~0.4s |

Payload sizes are application data, not ABI-encoded wire calldata. Pairwise gas numbers are measured on Anvil (Apple M-series); classical and direct ML-KEM are estimated from the ERC-5564 announcer gas model (no contract implementation in this PoC). ETH transfer is a constant 21K base transaction.

**10-payment channel comparison** (total gas for 10 payments to the same recipient):

| Model | Total gas | Total payload |
|-------|-----------|---------------|
| Classical (10 × announce + ETH) | ~680K (estimated) | 340 B |
| Direct ML-KEM (10 × announce + ETH) | ~852K (estimated) | 10,890 B |
| **Pairwise (1 first contact + 10 memos + ETH)** | **~629K (measured)** | **1,291 B** |

Classical and direct ML-KEM totals are computed from estimated per-payment gas. Pairwise total is derived from Anvil measurements: ~79K first contact + 10 × (~34K memo + 21K ETH) ≈ 629K (exact values vary slightly between runs due to calldata byte composition; see demo output). The pairwise payload advantage (~64× smaller than direct ML-KEM per payment) is the primary motivation; gas savings depend on the classical/direct announcer implementation.

**On-chain storage cost**: the 1,121 B first-contact ciphertext is stored as event calldata (not state), so it does not occupy persistent storage. At 16 gas/nonzero-byte and 30 gwei gas price, a first contact costs ~0.0005 ETH in calldata gas.

## Migration Path

A recipient can register both classical (ERC-5564 ECDH) and PQ (hybrid KEM) meta-addresses simultaneously. The registry stores both; legacy senders use the ECDH key, newer senders use the hybrid KEM. Over time, the ecosystem migrates. Key rotation: the recipient re-registers with new viewing keys; old first contacts remain decryptable with the old keys (which the seed can re-derive). Revocation is implicit — a new registration supersedes the old one.

## Direct ML-KEM as Default

For wallets prioritizing simplicity, direct ML-KEM (Model 1) is a stateless alternative: fresh encapsulation per payment, 1,089 B on-chain, no first contact, no k_pairwise, no nonce management. Estimated gas is ~85K per payment (estimated ~64K announcement + 21K ETH) vs ~55K for pairwise (34K measured + 21K ETH) — ~55% more, but zero complexity. A `registerKeysOnBehalf` function — already standardized in [ERC-6538](https://eips.ethereum.org/EIPS/eip-6538) with EIP-712 signature, nonce replay protection, and EIP-1271 smart wallet support — further improves onboarding by removing the need for recipients to hold public ETH. This PoC focuses on the pairwise channel because it is the novel contribution; direct ML-KEM is a trivial ECDH swap.

## Why Pairwise Channels Were Not Adopted Classically

BIP-47 (2015) proposed pairwise payment codes for Bitcoin — saw limited adoption because the 33 B ECDH ephemeral key is trivial, and stealth addresses provide unlinkability without persistent state.

In PQ, the 1,088 B ML-KEM ciphertext makes pairwise channels an economically motivated optimization: ~64× payload reduction (1,089 → 17 B) for active channels. Not a necessity — the direct replacement works without it — but a significant saving at ~16 gas/byte.

## Scope and Limitations

- **PQ key exchange**: ML-KEM-768 (NIST Level 3). Quantum-secure.
- **Stealth address spending**: secp256k1 ECDSA. Quantum-vulnerable — Google's 2026 research shows 256-bit EC curves breakable in minutes on superconducting architectures. Full PQ spending requires PQ transaction signatures at the Ethereum protocol level (EIP-7932). Our scope is the key exchange layer. The key exchange (ML-KEM first contact, `k_pairwise` derivation) carries forward to a PQ signature world unchanged; however, the stealth derivation mechanism (EC scalar addition) does not — see [Why EC Scalar Addition Has No PQ Replacement](#why-ec-scalar-addition-has-no-pq-replacement) below.
- **Stealth address lifespan**: recipients should sweep promptly. With a potential 2029 CRQC timeline, stealth addresses holding funds with exposed public keys are at direct risk. Sweeping moves funds to a fresh address whose public key is not yet on-chain.
- **Dependency**: `ml-kem = 0.3.0-rc.1` (pre-release, unaudited). Experimental research PoC.

### Why EC Scalar Addition Has No PQ Replacement

Stealth address derivation relies on a property unique to elliptic curve groups:

```
stealth_pk = spending_pk + hash(ss) * G      ← anyone with ss can compute (detection)
stealth_sk = spending_sk + hash(ss)           ← only spending key holder can compute (spending)
```

This works because the map `sk ↦ sk·G` is a **group homomorphism**: addition in the scalar field maps to addition on the curve. The public key can be offset without knowing the private key, but recovering the private key from the public key requires solving the discrete log. This asymmetry is what gives viewing/spending separation.

**What EC scalar addition provides:**

- **Viewing/spending separation**: `stealth_pk` is computable without `spending_sk`; deriving `stealth_sk` requires it. The homomorphism creates a one-way gap between detection and spending.
- **Sender safely computes destination**: the sender knows `spending_pk` (public) and `ss` → derives `stealth_addr` to send funds. Never needs `spending_sk`.
- **Compact memos**: the stealth address is *derived* (0 extra bytes), not *communicated*. The shared secret is already established.
- **Hardware wallet integration**: software sends offset scalar → hardware computes `spending_sk + offset` → signs. The spending secret never leaves the device.
- **Unlimited addresses, one registration**: a single `spending_pk` on-chain yields infinite stealth addresses with no pre-generation or interaction.

**What is lost without it:**

- **Sender can steal funds**: PQ `KeyGen(seed) → (pk, sk)` is monolithic — whoever derives the seed gets both keys. If the sender can compute `stealth_pk`, the sender also obtains `stealth_sk`.
- **EOA stealth addresses are impossible**: Ethereum EOAs derive `address = hash(public_key)`. Without the homomorphism, deriving the public key requires the spending secret — or reveals the private key to the sender. Neither is acceptable.
- **Memo payload grows**: the stealth address must be encrypted in the memo (~36 B) rather than derived, increasing per-payment calldata from 17 B to ~53 B.
- **Hardware wallet model breaks**: no offset scalar to send. The device must generate a full PQ keypair per stealth address.

**What survives independently of EC scalar addition:**

- **View tags**: `SHA-256("pq-sa-view-tag-v1" || ss)[0]` where `ss = SHA-256("pq-sa-pairwise-stealth-v1" || k_pairwise || nonce)` — pure symmetric crypto. Unchanged.
- **Pairwise channels**: ML-KEM first contact → `k_pairwise`. Unchanged in a fully PQ future (simplified to pure ML-KEM, dropping the ECDH half of the hybrid).
- **Scanning delegation**: view tags filter 99.6% of memos; the remaining require AES-GCM decryption (to recover the encrypted stealth address) instead of EC point addition. Functionally equivalent.
- **HNDL defense**: ML-KEM protects the first contact ciphertext. Unchanged.

**No NIST-standardized PQ signature scheme has the homomorphic property.** The obstacle is structural, not a parameter choice:

| Scheme | Key structure | Why offset fails |
|---|---|---|
| **Dilithium (ML-DSA)** | `t = A·s1 + s2`; security requires s1, s2 short | Short offset δ → `t' = t + A·δ` is close to `t` in the lattice (linkable). Large δ → `s1 + δ` breaks shortness assumption (signing fails or leaks key). Shared matrix `A` is a fingerprint across derived keys. |
| **Falcon** | `h = g/f mod q`; f, g short NTRU polynomials | `h' = g/(f+δ)` is not computable from `(h, δ)` without `g`. No public-only derivation path. |
| **SPHINCS+ (SLH-DSA)** | Hash-based Merkle trees | No algebraic structure at all. |

The root cause is deeper than any individual scheme. Shor's algorithm solves the Hidden Subgroup Problem for **abelian groups** — precisely the structure that makes EC scalar addition possible. Lattice-based schemes resist Shor because their security relies on the geometry of short vectors (LWE/SIS), not on group-theoretic structure. **The property that makes stealth derivation work (abelian group homomorphism) is the property that quantum computers exploit.**

| | Has group homomorphism | Shor-resistant | Stealth derivation |
|---|---|---|---|
| EC (secp256k1) | Yes | No | Yes |
| CSIDH (isogeny) | Yes (class group action) | Partially (subexponential quantum) | Yes |
| Lattice (Dilithium, Falcon) | No | Yes | No |
| Hash-based (SPHINCS+) | No | Yes | No |

[CSIDH](https://ethresear.ch/t/towards-practical-post-quantum-stealth-addresses/15437) (asanso 2023) is the only PQ family with a usable group action for stealth addresses — but its quantum security is subexponential (Kuperberg's algorithm), not polynomial-time-hard, and operations are orders of magnitude slower than EC. It is not on any NIST standards track.

An alternative approach avoids the homomorphism entirely: PQ KeyGen is monolithic — `seed → (pk, sk)` — so whoever can derive the public key can also derive the private key. This means fully PQ stealth addresses cannot use EOAs (where `address = hash(public_key)`). Instead, they require **smart contract wallets** where spending is enforced by on-chain signature verification:

```
stealth_addr = CREATE2(factory, salt=hash(k_pairwise || nonce), wallet_code(spending_pk))
```

The sender computes the address from public data (`spending_pk`, `salt`), but spending requires a PQ signature verified by the contract — only the holder of `spending_pk`'s corresponding secret key can sign. Detection still works: view tags are symmetric crypto (independent of the signature scheme), and the stealth address can be encrypted in the memo under `k_view` for scanning delegation. This aligns with Ethereum's account abstraction direction (ERC-4337, EIP-7702) and is likely required for PQ transaction signatures regardless (ML-DSA-44 signatures are 2,420 B at NIST Level 2; ML-DSA-65 is 3,309 B at Level 3 — too large for current EOA verification).

[Mikic et al. 2025](https://arxiv.org/html/2501.13733v1) is the only published scheme that achieves PQ viewing/spending separation, using custom Module-LWE arithmetic — but it is not Ethereum-compatible and does not target existing account models.

**This work is explicitly transitional**: we upgrade the key exchange layer to PQ (ML-KEM-768) while retaining EC scalar addition for stealth derivation. The key exchange is the urgent layer — it protects against HNDL today. The stealth derivation layer is a different threat model: it requires an active quantum computer at spend time, not passive recording. The migration path to fully PQ stealth addresses is an open research problem that depends on account abstraction and PQ signature integration at the protocol level.

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

## Privacy Protocol Landscape

Every major private transfer protocol uses ECDH-based key exchange for note encryption — all vulnerable to HNDL:

| Protocol | Note Discovery | Delegated? | PQ? |
|----------|---------------|------------|-----|
| **Zcash** | Trial decrypt all outputs | No (compact blocks, local decrypt) | No |
| **Penumbra** | Fuzzy Message Detection + trial decrypt | Yes (coarse filter delegated) | No |
| **Railgun** | Trial decrypt (local WASM) | No | No |
| **Umbra** | ECDH + view tag + subgraph indexing | Semi (Graph Protocol) | No |
| **Nocturne** (defunct) | ECDH trial decrypt | No | No |
| **Panther** | ECDH trial decrypt | No | No |
| **Manta** | Viewing key trial decrypt | No | No |

The universal pattern: **ECDH key exchange → encrypted note → trial decrypt**. This work upgrades the first step (ECDH → hybrid KEM) for HNDL defense. [pq_SA_OMR](https://github.com/namnc/pq_SA_OMR) optimizes the scanning step (trial decrypt → OMR via Pasta-4 transciphering). Both apply to any protocol in this table — the curve and hash are parameter choices.

Penumbra's S-FMD is the only deployed scanning delegation, but it leaks probabilistic detection to the server. True OMR (fully oblivious) is not deployed anywhere yet.

## Applicability to Aztec Note Discovery

Aztec's [note discovery](https://docs.aztec.network/developers/docs/foundational-topics/advanced/storage/note_discovery) uses the same pattern: shared secret → tag derivation → scan. They identify OMR as a "long-term goal" that's "currently impractical." This work provides two applicable components:

1. **PQ shared secret** (pq_SA): replace Grumpkin ECDH with hybrid KEM. Tag derivation stays the same — just the shared secret source becomes PQ-secure. Non-interactive first contact solves Aztec's "can't receive from unknown sender" limitation.
2. **Practical OMR** ([pq_SA_OMR](https://github.com/namnc/pq_SA_OMR)): Regev → Pasta substitution reduces OMR signal from ~2 KB to 128 B. The curve (Grumpkin) and hash (Poseidon2) are parameter choices, not architectural constraints.

## Future Work

- **Full PQ spending**: PQ transaction signatures (Dilithium, Falcon) via EIP-7932 would close the remaining quantum gap at the signing layer. However, as discussed in [Why EC Scalar Addition Has No PQ Replacement](#why-ec-scalar-addition-has-no-pq-replacement), the stealth address derivation mechanism (EC scalar addition) has no direct PQ equivalent. Fully PQ stealth addresses likely require smart contract wallets (ERC-4337) where spending is enforced by on-chain PQ signature verification, not key-homomorphic derivation. The key-exchange layer (this work) carries forward unchanged.
- **ML-KEM-1024**: Level 5 security at 1,568 B ciphertext — the pairwise optimization becomes even more valuable (1,568 B amortized to 17 B).
- **Cross-chain**: L2s (Arbitrum, Optimism) already adopt ERC-5564. The pairwise approach works identically; only calldata pricing differs.
- **Privacy-enhanced view tags**: PRF-derived tags (instead of hash truncation) could reduce metadata leakage from tag collisions. Optional 2-byte tags for high-volume services would reduce false positives to 0.0015%.
- **Threshold viewing**: `t-of-n` viewing key sharing for multi-party compliance (e.g., custodial services that require multiple parties to detect payments).

## Related Work

- [CRQC Timeline](https://words.filippo.io/crqc-timeline/) — Filippo Valsorda, 2026. CRQC by ~2029.
- [Quantum bombshells](https://scottaaronson.blog/?p=8669) — Scott Aaronson, 2026. Google: ~25K physical qubits for 256-bit EC curves.
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

- Hy Ngo — Review and audit
- Platus team — `registerKeysOnBehalf` and direct ML-KEM UX recommendations
- Vikas — Sepolia ETH for testnet deployment
- Keewoo Lee — Discussion on PQ privacy
