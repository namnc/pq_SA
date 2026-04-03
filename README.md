# pq_SA

**Post-Quantum Stealth Addresses for Ethereum**

A proof-of-concept implementing post-quantum private note encryption and discovery on Ethereum. Combines classical ECDH with ML-KEM-768 in a hybrid KEM construction, uses ChaCha20-Poly1305 for authenticated encryption, and RS(8,4) erasure coding for data availability across independent servers.

Live on Sepolia: [`0x07EB0C4D70041D2B4CAC38cAB9bd2360d0639E6E`](https://sepolia.etherscan.io/address/0x07EB0C4D70041D2B4CAC38cAB9bd2360d0639E6E)

## Why

Current Ethereum privacy systems (stealth addresses, note encryption) rely on ECDH or similar constructions that a cryptographically-relevant quantum computer would break. ML-KEM (FIPS 203) is quantum-resistant, but has no read-only key subset — the decapsulation key *is* the full secret.

BIP-47 (2015) proposed pairwise payment codes for Bitcoin — the same pattern. It was saw limited adoption classically because the 33 B ECDH ephemeral key is trivial, 1-byte view tags filter 99.6% of notes, and viewing keys enable safe delegation. None of these hold for ML-KEM: the ciphertext is 1,088 B (33x larger), no view tag exists (no viewing key to derive one from), and delegation requires giving away the spending key. Pairwise channels are PQ-*necessary*, not just convenient — the classical failure of BIP-47 does not predict the PQ outcome.

This PoC demonstrates a hybrid approach: ECDH for transitional compatibility, ML-KEM-768 for post-quantum security, combined via HKDF-SHA256 into a single pairwise key. If either primitive holds, the channel is secure.

## Architecture

```
Sender                                    Ethereum (Sepolia)                          Recipient
  |                                            |                                         |
  |  1. Look up recipient's pk_ec + ek_kem     |                                         |
  |<--- KeyRegistered event -------------------|                                         |
  |                                            |                                         |
  |  2. Hybrid KEM: ECDH + ML-KEM-768         |                                         |
  |     k_pairwise = HKDF(ss_ec || ss_pq)     |                                         |
  |                                            |                                         |
  |  3. Encrypt note: ChaCha20-Poly1305       |                                         |
  |                                            |                                         |
  |  4. postFirstContact(commitment, payload)  |                                         |
  |---> calldata: epk(33) + ct_pq(1088)  ---->|  FirstContact event                     |
  |              + nonce(16) + ct(632)         |                                         |
  |                                            |--- scan events --->  5. Decapsulate     |
  |                                            |                      6. Decrypt          |
  |                                            |                      7. Verify commitment|
  |  Subsequent notes (known-pair):            |                                         |
  |---> postNote(commitment, nonce, ct) ------>|  NotePosted event  ---> decrypt ------->|
  |     48 B minimum calldata                  |                                         |
```

## Cryptographic Primitives

| Primitive | Implementation | Purpose |
|-----------|---------------|---------|
| ECDH | secp256k1 | Classical key agreement (transitional) |
| ML-KEM-768 | FIPS 203 via `ml-kem` crate | Post-quantum KEM (NIST Level 3) |
| HKDF-SHA256 | RFC 5869 | Hybrid key derivation |
| ChaCha20-Poly1305 | RFC 8439 | Authenticated encryption (632 B ciphertext) |
| SHA-256 | Commitment & channel ID derivation | |
| HMAC-SHA256 | Per-shard authentication | |
| Reed-Solomon RS(8,4) | Erasure coding across 8 servers | |

## Project Structure

```
pq-sa/
├── contracts/                  # Solidity (Foundry)
│   ├── src/NoteRegistry.sol    #   On-chain event log (92 lines)
│   └── test/NoteRegistry.t.sol #   6 Foundry tests
├── crates/
│   ├── primitives/             # Core cryptographic library
│   │   ├── src/
│   │   │   ├── hybrid_kem.rs   #   ECDH + ML-KEM-768 hybrid KEM
│   │   │   ├── aead.rs         #   ChaCha20-Poly1305 encrypt/decrypt
│   │   │   ├── erasure.rs      #   RS(8,4) encode/decode + per-shard HMAC
│   │   │   ├── note.rs         #   NotePlaintext (616 B serialized)
│   │   │   ├── commitment.rs   #   SHA-256 note commitment + nullifier seed
│   │   │   ├── channel.rs      #   channel_id and msg_id derivation
│   │   │   └── shard.rs        #   ShardHeader + ShardWithHmac serialization
│   │   └── tests/e2e.rs        #   5 integration tests
│   ├── sidecar/                # Filesystem-based blob DA simulation
│   ├── demo/                   # End-to-end on-chain demo binary
│   ├── sender/                 # Sender CLI (stub)
│   └── recipient/              # Recipient CLI (stub)
├── Cargo.toml                  # Workspace root
└── README.md
```

## Quick Start

### Prerequisites

- Rust 1.91+ (`rustup update stable`)
- Foundry (`curl -L https://foundry.paradigm.xyz | bash && foundryup`)

### Build

```bash
# Build Solidity contracts first (demo depends on compiled ABI)
cd contracts && forge build && cd ..

# Build Rust workspace
cargo build --release
```

### Run Tests

```bash
# Rust: 37 tests
cargo test --release

# Solidity: 27 tests
cd contracts && forge test -vv
```

### Run Demo on Anvil (local)

```bash
# Terminal 1: start local testnet
anvil

# Terminal 2: run the full sender → recipient flow (uses separate sender + recipient wallets)
cargo run -p demo --release
```

Expected output:

```
================================================
  PQ In-Band Secret Distribution — Testnet Demo
================================================

[contract] Deploying NoteRegistry (archivalVault=0x0)...
[contract] Deployed at: 0x07EB0C...

--- RECIPIENT: Key Generation ---
  pk_ec:  034be0fa00bedf29... (33 B)
  ek_kem: c2d9a3854ac7c2f8... (1184 B)

--- SENDER: Posting first contact on-chain ---
  gas:    117462

--- RECIPIENT: Scanning chain for FirstContact events ---
  ** DECRYPTED: value = 1000000 **
  Commitment verified OK

--- RECIPIENT: Scanning chain for NotePosted events ---
  ** DECRYPTED: value = 500000 **
  Commitment verified OK

--- RECIPIENT: Depositing subscription balance ---
  deposit: 0.0001 ETH

--- RECIPIENT: Spending note 0 (pay-on-spend) ---
  gas:       51123
  nullifier: 0xfc7215...
  spent:     true
```

### Run Demo on Sepolia

```bash
cargo run -p demo --release -- \
  --rpc https://ethereum-sepolia-rpc.publicnode.com \
  --private-key 0xYOUR_FUNDED_PRIVATE_KEY
```

Or reuse the deployed contract:

```bash
cargo run -p demo --release -- \
  --rpc https://ethereum-sepolia-rpc.publicnode.com \
  --private-key 0xYOUR_FUNDED_PRIVATE_KEY \
  --contract 0x07EB0C4D70041D2B4CAC38cAB9bd2360d0639E6E
```

## On-Chain Costs (Sepolia)

| Transaction | Calldata | Gas Used |
|-------------|----------|----------|
| Register keys (one-time) | 1,217 B (33 + 1184) | ~77K |
| First contact | 1,769 B (epk + ct_pq + nonce + ct) | ~117K |
| Known-pair note | 680 B (commitment + nonce + ct) | ~74K |

At 30 gwei gas price: first contact costs ~0.0035 ETH, subsequent notes ~0.0022 ETH. The contract stores `noteCommitments` on-chain to support receiver-pays archival (~22K gas SSTORE overhead per note).

## Protocol Details

### First Contact (Channel Establishment)

1. Sender generates ephemeral secp256k1 keypair `(esk, epk)`
2. ECDH: `ss_ec = ECDH(recipient.pk_ec, esk)[0:32]`
3. ML-KEM-768: `(ct_pq, ss_pq) = Encapsulate(recipient.ek_kem)`
4. Hybrid KDF: `k_pairwise = HKDF-SHA256(ss_ec || ss_pq, "pq-sa-v1", 32)`
5. Encrypt note: `ct = ChaCha20-Poly1305(k_pairwise, nonce, plaintext)`
6. Post on-chain: `postFirstContact(commitment, epk || ct_pq || nonce || ct)`

### Known-Pair Notes (Subsequent)

Reuse `k_pairwise` from first contact. Only `commitment + nonce + ciphertext` goes on-chain (48 B minimum without ciphertext, 680 B with).

### Erasure Coding

Each encrypted note (632 B) is RS(8,4) encoded into 8 shards (158 B each) with per-shard HMAC-SHA256. Any 4 of 8 valid shards reconstruct the original. Tested across all C(8,4) = 70 combinations.

#### Why erasure coding matters

The encrypted note is distributed across M=8 independent servers (simulating blob DA providers). Without erasure coding, every server must be online for the recipient to recover the note — a single server going offline loses the data. With RS(8,4), the recipient needs only **any 4 of 8** servers to respond.

#### Concrete example

Alice sends Bob an encrypted note worth 1 ETH. The 632-byte ciphertext is split and encoded into 8 shards:

```
Encrypted note (632 B)
  ├── split into 4 data chunks (158 B each)
  ├── RS encode → 4 parity chunks (158 B each)
  └── each chunk gets an HMAC-SHA256 tag (32 B)

Shard 0: [header 21 B] [data 158 B] [hmac 32 B] → Server A
Shard 1: [header 21 B] [data 158 B] [hmac 32 B] → Server B
Shard 2: [header 21 B] [data 158 B] [hmac 32 B] → Server C
Shard 3: [header 21 B] [data 158 B] [hmac 32 B] → Server D
Shard 4: [header 21 B] [data 158 B] [hmac 32 B] → Server E  (parity)
Shard 5: [header 21 B] [data 158 B] [hmac 32 B] → Server F  (parity)
Shard 6: [header 21 B] [data 158 B] [hmac 32 B] → Server G  (parity)
Shard 7: [header 21 B] [data 158 B] [hmac 32 B] → Server H  (parity)
```

Now suppose servers B, C, E, and G go offline. Bob can only reach servers A, D, F, and H — that's 4 servers, which is exactly the threshold. Bob downloads shards 0, 3, 5, 7, verifies their HMACs, reconstructs the full 632-byte ciphertext, and decrypts the note.

If a malicious server (say F) returns corrupted data, the HMAC check fails. Bob discards that shard and treats it as missing. He now has 3 valid shards — not enough. But if at least one more server comes back online, he recovers the note.

#### Failure tolerance

| Scenario | Servers responding | Valid shards | Outcome |
|----------|-------------------|-------------|---------|
| All healthy | 8 of 8 | 8 | Recovered |
| Minor outage | 6 of 8 | 6 | Recovered |
| Half down | 4 of 8 | 4 | **Recovered** (minimum) |
| Half down + 1 corrupt | 4 of 8 | 3 | **Failed** (below threshold) |
| Majority down | 3 of 8 | 3 | Failed |
| 2 corrupted + 2 offline | 6 responding, 4 valid | 4 | **Recovered** |

The system tolerates **any combination of up to 4 failures** (offline + corrupted). The HMAC tags ensure corrupted shards are detected and excluded rather than silently poisoning the reconstruction.

#### Multi-note channels and unreliable DA

This is the more important case. In a pairwise channel, Alice sends Bob many notes over weeks or months — 20, 50, 100 notes. Each note is independently erasure-coded across the same 8 servers. The question becomes: can Bob recover **all** his notes, not just one?

**Why this matters more than single notes**: Blob DA is cheaper than calldata but less reliable. Servers go offline, rotate, or get decommissioned. A system that works for a single note but loses notes over a long-running channel is useless for real payments.

**Concrete scenario**: Alice sends Bob 20 notes over a month.

```
Week 1: notes 1-5 sent. All 8 servers healthy.
  Bob recovers all 5. ✓

Week 2: notes 6-10 sent. Server C goes offline.
  Bob has 7 servers for each note. Recovers all 5. ✓

Week 3: notes 11-15 sent. Servers C and E still offline.
  Bob has 6 servers. Recovers all 5. ✓

Week 4: notes 16-20 sent. Servers C, E, F, G, H all offline (5 of 8).
  Bob has only 3 servers (A, B, D). Below threshold. ✗ CANNOT recover.

Day 30: Server F comes back online.
  Bob now has 4 servers (A, B, D, F) for notes 16-20. Recovers all 5. ✓
```

The key property: **recovery is retroactive**. Bob doesn't need 4 servers to be online at the moment the note was sent — he needs 4 servers to have the shard at any point when he tries to recover. Notes 1-15 were never at risk because they were recovered while servers were healthy. Notes 16-20 were temporarily stuck but recovered once one server came back.

**Without erasure coding** the same scenario is catastrophic:

```
Without erasure coding: each note stored on 1 server
  Note 1 → Server A (online) ✓
  Note 2 → Server B (online) ✓
  Note 3 → Server C (offline) ✗ LOST
  Note 4 → Server D (online) ✓
  ...
  Any single server failure permanently loses that note.
```

Or if you replicate to all 8 servers (no coding, just copies):

```
Simple replication: full copy on every server
  Each note: 632 B × 8 servers = 5,056 B total storage
  Tolerates 7 of 8 failures — very resilient
  But 8x storage overhead (vs 2x with RS(8,4))
```

RS(8,4) is the sweet spot: 2x storage overhead, tolerates up to 4 simultaneous failures.

#### Probability over many notes

If each server has independent uptime probability p per retrieval attempt:

| Server uptime | 1 note recovered | 20 notes (independent) | 20 notes (persistent failure) |
|---------------|-----------------|----------------------|------------------------------|
| 95% | 99.998% | 99.96% | 99.998% |
| 90% | 99.94% | 98.8% | 99.94% |
| 80% | 98.96% | 81.1% | 98.96% |
| 70% | 94.2% | 30.3% | 94.2% |

The "independent" column assumes each server flips a coin per note — worst case, unrealistic. The "persistent failure" column assumes servers that are down stay down — all notes are affected equally, so recovering any one note means recovering all of them. Reality is between these extremes.

The practical takeaway: at 90% server reliability, a single note without erasure coding has a 90% chance of being recoverable. With RS(8,4), that jumps to **99.94%**. Over a 20-note channel, the uncoded system loses ~2 notes on average. The erasure-coded system loses none with 99.94% probability.

#### Channel-aware retry

Because Bob tracks his pairwise channel with Alice, he knows exactly which notes to expect (via on-chain commitments and nonces). If a note can't be recovered today, he can retry tomorrow. This is fundamentally different from the no-channel baseline, where missing a note means not even knowing it existed.

```
Bob's channel state:
  note 1: recovered ✓  (k_pairwise, nonce_1 → plaintext)
  note 2: recovered ✓
  note 3: pending    ⏳ (commitment seen on-chain, only 3 shards available)
  note 4: recovered ✓
  note 5: pending    ⏳ (retrying, server F coming back soon)
```

#### Overhead

Erasure coding doubles the total storage (8 shards x 158 B = 1,264 B vs 632 B original), but each server stores only 211 B per note (158 B data + 21 B header + 32 B HMAC). This is a 2x overhead for the ability to lose half the servers and still recover every note in a long-running channel.

The PoC tests all C(8,4) = 70 possible 4-of-8 shard combinations and verifies that every one correctly reconstructs the original ciphertext.

### Note Structure

```
NotePlaintext (616 B):
  value:           u64     (8 B)
  asset_id:        [u8;32] (32 B)
  blinding_factor: [u8;32] (32 B)
  memo:            [u8;512](512 B)
  nullifier_seed:  [u8;32] (32 B)
```

After ChaCha20-Poly1305 encryption: 632 B (616 + 16 B auth tag).

## The PQ Tax: Classical vs Post-Quantum Cost

The central question: **how much does quantum resistance cost?**

Run `cargo run -p classical --release` for measured classical gas. The naive PQ approach (fresh ML-KEM per note) adds 1,088 B of KEM ciphertext to every note — a permanent 150% overhead over classical ECDH. Pairwise channels reduce this overhead from **per-note to per-channel**: the 1,088 B appears once at first contact, then amortizes toward zero as the channel grows.

### Measured (Anvil)

| | Classical (ECDH-only) | PQ naive (per-note KEM) | PQ pairwise (this repo) |
|--|----------------------|------------------------|------------------------|
| **Calldata/note** | 709 B | 1,732 B | 1st: 1,769 B, then: **680 B** |
| **Gas/note** | ~74K | ~100K | 1st: ~117K, then: **~74K** |
| **PQ security** | None | ML-KEM-768 | Hybrid ECDH + ML-KEM-768 |
| **KEM overhead** | 0 B (reference) | **1,088 B every note** | **1,088 B once** |

### Amortized KEM overhead per note

The PQ KEM ciphertext (1,088 B / ~26K gas) is the cost of quantum resistance. Without pairwise channels, every note pays it. With pairwise channels, the channel pays it once — overhead per note approaches zero as channel length grows.

| Channel length (N) | Naive PQ overhead/note | **Pairwise PQ overhead/note** |
|---|---|---|
| 1 | 1,088 B / 26K gas | 1,092 B / 26K gas |
| 5 | 1,088 B / 26K gas | 218 B / 5.3K gas |
| 10 | 1,088 B / 26K gas | 109 B / 2.6K gas |
| 50 | 1,088 B / 26K gas | **22 B / 527 gas** |
| N | 1,088 B (constant) | **1,092/N → 0** |

The gas overhead (26K) compares first-to-first: PQ first contact (117K) vs classical first note (91K). Subsequent notes are effectively identical: PQ known-pair (~73.5K) vs classical (~74K) — PQ is ~450 gas cheaper because the pairwise channel eliminated the 33 B ephemeral key.

**Calldata crossover at N=39**: total PQ calldata equals total classical calldata.
**Gas crossover at N~50-60**: total PQ gas equals total classical gas (varies by ~450-500 gas/note measurement noise).

```
Per-note KEM overhead vs classical:

Naive PQ  |=========================================================| 1,088 B (every note)
N=1       |=========================================================| 1,092 B
N=5       |===========|                                                218 B
N=10      |=====|                                                      109 B
N=50      |=|                                                           22 B
Classical |==|  33 B ephemeral key (every note, but no PQ security)
```

## Progressive Improvements

Each stage solves a specific problem left by the previous one. Run `cargo run -p bench --release` and `cargo run -p baseline --release` to reproduce measured numbers.

### Stage 0: Baseline — Naive ML-KEM-768

The simplest post-quantum approach: for every note, the sender runs a fresh ML-KEM-768 key encapsulation, derives an encryption key from the shared secret, and posts the KEM ciphertext alongside the encrypted note on-chain.

**What it does right**: Post-quantum security. ML-KEM-768 (FIPS 203, NIST Level 3) resists quantum attacks.

**What it does wrong**: The ML-KEM ciphertext is **1,088 bytes**, and it appears in every single note. The sender also performs a lattice operation (encapsulation) for every note — even if sending to the same recipient repeatedly.

```
Baseline: every note on-chain
  [ML-KEM ciphertext 1,088 B] [nonce 12 B] [encrypted note 632 B] = 1,732 B
  [ML-KEM ciphertext 1,088 B] [nonce 12 B] [encrypted note 632 B] = 1,732 B
  [ML-KEM ciphertext 1,088 B] [nonce 12 B] [encrypted note 632 B] = 1,732 B
  ...same cost every time
```

**Measured** (Anvil): **~100K gas per note** (first note ~117K, subsequent ~99K), 1,732 B calldata per note, one ML-KEM encap+decap per note.

### Stage 1: PoC A — Pairwise Channels (this repo)

**Problem**: The baseline wastes 1,088 B of calldata on every note, even between parties who have already exchanged keys.

**Solution**: The first note between a sender-recipient pair establishes a **pairwise channel** using a hybrid KEM (ECDH + ML-KEM-768). This produces a shared symmetric key `k_pairwise`. All subsequent notes reuse that key — just ChaCha20-Poly1305 encryption with no lattice operations.

```
PoC A: first contact pays the KEM cost; subsequent notes don't
  [epk 33 B] [ML-KEM ct 1,088 B] [nonce 16 B] [encrypted note 632 B] = 1,769 B  (first contact)
  [commitment 32 B] [nonce 16 B] [encrypted note 632 B]               =   680 B  (known-pair)
  [commitment 32 B] [nonce 16 B] [encrypted note 632 B]               =   680 B  (known-pair)
  ...680 B from now on
```

**Measured** (Anvil): First contact **~117K gas**, known-pair **~74K gas** (25% less). After 5 notes to the same recipient, total gas is 27% lower than baseline. Sender CPU is 6.5x faster at 50 notes because subsequent notes use only symmetric crypto.

| | Baseline | PoC A (1st note) | PoC A (subsequent) |
|--|---------|-----------------|-------------------|
| Calldata | 1,732 B | 1,769 B | **680 B** |
| Gas | ~100K | ~117K | **~74K** |
| Lattice ops | 1 per note | 1 (first only) | **0** |
| CPU (send) | ~32 us | ~168 us | **~2 us** |

**What it doesn't solve**: The recipient still has no way to know which notes on-chain are theirs without trying to decrypt every one. With 10K notes/day and 50 sender channels, that's 500K trial decryptions per day.

### Stage 2: Naive OMR — Fix Scanning, Break Calldata

**Problem**: The recipient scans every note by trial decryption. This is O(N x S) — it works, but doesn't scale.

**How OMR helps**: Oblivious Message Retrieval (Liu & Tromer, 2021) lets the sender attach a detection clue to each note. An OMR server evaluates all clues under fully-homomorphic encryption (FHE) and returns an encrypted digest (~300-400 KB) containing pertinent **note IDs**. The recipient then fetches payloads using a padded request (always k_bar=50 notes, padding with random IDs) so the sidecar sees a constant-size request with no access pattern leak. The server learns nothing.

**The catch**: A standard PVW detection clue with 128-bit post-quantum security is a lattice ciphertext — roughly **2 KB per note**. This is larger than the encrypted note itself. And the ciphertext must stay on calldata too — the recipient can't move it to blobs because they don't know which notes are theirs until the OMR digest arrives.

```
Naive OMR: scanning is solved, but calldata gets worse
  [commitment 32 B] [nonce 16 B] [PVW clue ~2,048 B] [encrypted note 632 B] = ~2,728 B
  ...every note
```

The recipient no longer trial-decrypts, but the sender now pays **~1,600-2,700 B of calldata per note (depends on PVW params)** — 4x more than PoC A's known-pair notes and worse than the baseline.

| | PoC A (no OMR) | Naive OMR |
|--|---------------|-----------|
| Calldata/note | 680 B | **~1,600-2,728 B (2-4x worse, depends on PVW params)** |
| Gas/note | ~74K | **~123K (66% worse)** |
| Recipient scan | O(N x S) trials | **sublinear (digest-based)** |
| At 10K notes/day | 6.8 MB calldata | **27.3 MB calldata** |
| ETH/day (calldata gas, 30 gwei) | 22.1 | 29-37 |

Naive OMR trades cheap recipient scanning for expensive on-chain data. At scale, this is worse economics.

### Stage 3: PoC B — Transciphered OMR (separate repo, planned)

**Problem**: Naive OMR's PVW clues are too large for calldata (~1,600-2,700 B). We need sublinear scanning (digest-based) without the calldata penalty.

**Solution**: Pasta-4 transciphering compresses the on-chain detection footprint from ~1,600-2,700 B to **104 B** while moving ciphertext to blobs. See the [companion PoC B post](../ethresearch_post_poc_b.md) for full FHE depth analysis and implementation plan.

| | PoC A | Naive OMR | **PoC B** |
|--|-------|-----------|-----------|
| **Calldata/note** | 680 B | ~1,600-2,700 B | **104 B** (+700 B blob) |
| **Gas/note** | ~74K | ~123K | **~60-75K** (projected) |
| **Recipient scan** | O(N x S) AEADs | sublinear (digest) | **sublinear** |

PoC B depends on a BFV depth benchmark (composed depth 8-10 in a budget of 14) that has not yet been run. If it fails, PoC A remains standalone.

### Summary

```
Calldata per known-pair note:

Naive OMR    |=============================================| ~1,600-2,700 B
Baseline     |=================================|                    1,732 B
Classical    |=============|                                          709 B
PoC A        |============|                                           680 B  (≈ classical)
PoC B        |==|                                                     104 B  (+700 B blob)
```

| Stage | Solves | Measured/Projected |
|-------|--------|-------------------|
| Classical | ECDH-only (no PQ) | ~74K gas, 709 B/note (measured) |
| Baseline | PQ security (naive) | ~100K gas, 1,732 B/note (measured) |
| **PoC A (this repo)** | PQ + pairwise amortization | **~74K gas, 680 B/note (= classical cost)** (measured) |
| PoC B (separate repo) | Scanning without calldata penalty | ~60K gas, 104 B/note (projected) |

## Fee Model and Spam Prevention

In a privacy system, the contract can't distinguish legitimate notes from spam — any content-based filtering would leak information. The system doesn't try to define or detect spam. Instead, **every note pays its own processing cost**, making the distinction irrelevant.

### Two fees, two payers

| Fee | Who pays | When | Covers | Refundable? |
|-----|---------|------|--------|------------|
| **Sender fee** | Sender | At post time (`msg.value`) | FHE processing (transciphering + PVW detection) | No |
| **Spend fee** | Recipient | At spend time (`spendNote`) | Archival + retrieval + server margin | Deducted from balance |

**Sender fee** (~$0.001/note): Paid upfront when posting. Non-refundable. Covers the OMR server's marginal cost of transciphering this note under FHE. This IS the spam prevention — you can't post without paying, and the server is compensated for every note it processes regardless of whether it's "spam" or not.

**Spend fee** (~$0.001/note): Deducted from recipient's pre-deposited balance when spending (nullifying) a note. Covers long-term archival and retrieval. Recipient deposits a subscription balance upfront; unused balance is withdrawable.

```solidity
// Sender posts note with processing fee
registry.postNote{value: senderFee}(commitment, nonce, ciphertext);

// Recipient pre-funds subscription
registry.depositBalance{value: 1 ether}();

// Recipient spends note — spend fee deducted, nullifier recorded
registry.spendNote(noteId, nullifier);
```

### Why not bonds?

We considered a bond model (sender posts refundable bond, forfeited if note is never spent). This fails because **"unspent" is not the same as "spam"** — a legitimate note may be slow to spend (recipient offline, small amount, memo-only). Penalizing unspent notes penalizes legitimate slow spenders. The flat sender fee avoids this: every note is self-funding, no expiry needed.

### Why this works as spam prevention

The attacker's only option is to outspend the server's processing capacity. But the fee scales linearly with the attack:

| Attack volume | Attacker cost (fees + gas) | Server revenue | Server capacity |
|--------------|--------------------------|---------------|----------------|
| 10K notes/day (normal) | ~$10 + $700 gas | $10 | Funded |
| 100K spam/day | ~$100 + $7K gas | $100 | Scales with revenue |
| 1M spam/day | ~$1K + $70K gas | $1K | Scales with revenue |

The server can always add hardware funded by the attacker's own fees. This is the same insight behind Bitcoin's fee market: miners don't care if a transaction is "spam" — they care if it pays enough.

### Data availability and blob archival

EIP-4844 blobs are pruned after ~18 days. The sender fee covers FHE processing; the spend fee covers long-term archival via the server or EthStorage (~$0.0001/note for decentralized persistence). For production, the OMR server can act as an ERC-4337 paymaster, bundling privacy relay + archival + OMR into one recipient subscription.

The contract supports both fee types simultaneously (20 Foundry tests).

## Security Considerations

- **Hybrid security**: If either ECDH or ML-KEM-768 holds, the pairwise key is secure
- **Implicit rejection**: ML-KEM decapsulation with wrong key returns a pseudorandom shared secret; AEAD decryption then fails cleanly
- **Constant-time HMAC**: Shard verification uses HMAC `verify_slice` (constant-time comparison)
- **Deterministic key recovery**: `RecipientKeyPair::from_seed` enables wallet recovery from a 32-byte seed
- **No sender identity on-chain**: Sender address is visible in tx metadata; production should use a relayer/paymaster

### What This PoC Does NOT Cover

- **Oblivious Message Retrieval (OMR)**: Transciphered Pasta-4 signal compression under BFV FHE is specified but not implemented (separate PoC B)
- **PQ viewing keys**: ML-KEM has no read-only key subset; this is an open problem
- **Poseidon commitments**: Uses SHA-256; production should use Poseidon-256 over BN254
- **Blob transactions (EIP-4844)**: Shards use calldata; production targets blob DA

## Test Coverage

**37 Rust tests + 27 Foundry tests = 64 total**

| Module | Tests | Coverage |
|--------|-------|----------|
| hybrid_kem | 4 | Roundtrip, wrong recipient, deterministic seed, ciphertext sizes |
| aead | 5 | Roundtrip, wrong key/nonce, tampered ciphertext, note-sized payload |
| erasure | 7 | Encode, roundtrip, minimum shards, insufficient shards, corruption, wrong key, all 70 combinations |
| commitment | 5 | Deterministic, changes with plaintext/addr, nullifier seed |
| channel | 3 | Deterministic channel_id/msg_id, different inputs |
| note | 2 | Serialize roundtrip, size check |
| shard | 2 | Header and shard-with-HMAC roundtrip |
| sidecar | 4 | Write/read, missing returns None, list notes, partial reads |
| e2e | 5 | First contact, erasure coding, wrong recipient, wallet recovery, multi-sender |
| NoteRegistry.sol | 20 | Core: register, bad length, first contact, note, ID increment, epoch. Archival: sender-pays, receiver-pays, nonexistent, missing fee, no-fee, no-vault. Subscription: deposit, withdraw, insufficient. Spend: pay-on-spend, double-spend, insufficient balance, zero fee, nonexistent. |

## Dependencies

| Category | Crate | Version |
|----------|-------|---------|
| PQ KEM | `ml-kem` | 0.3.0-rc.1 (FIPS 203) |
| KEM traits | `kem` | 0.3.0-rc.6 |
| Classical EC | `secp256k1` | 0.29 |
| AEAD | `chacha20poly1305` | 0.10 |
| KDF | `hkdf` | 0.12 |
| Hash | `sha2` | 0.10 |
| MAC | `hmac` | 0.12 |
| Erasure coding | `reed-solomon-erasure` | 6.0 |
| Ethereum | `alloy` | 1.8 |
| Solidity | Foundry / Solc 0.8.33 | |

## ERC Draft

An ERC is drafted at [`ERC-XXXX.md`](ERC-XXXX.md) to standardize the on-chain interface. It defines three interfaces:

- **`IERC_XXXX_KeyRegistry`** — Register hybrid PQ key material (classical EC + ML-KEM) with scheme IDs for algorithm agility
- **`IERC_XXXX_NoteRegistry`** — Two-phase note posting (first-contact with KEM ciphertext, known-pair with symmetric-only)
- **`IERC_XXXX_Incentives`** — Subscription deposit, pay-on-spend with nullifier-based double-spend prevention

The standard is designed to coexist with ERC-5564 (stealth addresses) and ERC-6538 (stealth meta-address registry). A wallet can register both classical stealth meta-addresses and PQ keys simultaneously.

## Related Work

- [BIP-47](https://github.com/bitcoin/bips/blob/master/bip-0047.mediawiki) — Reusable payment codes (2015)
- [ERC-5564](https://eips.ethereum.org/EIPS/eip-5564) — Stealth addresses
- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) — ML-KEM standard
- [Oblivious Message Retrieval](https://eprint.iacr.org/2021/1256) — Liu & Tromer (2021)

## Acknowledgements

- Vikas — Sepolia ETH for testnet deployment
- Keewoo Lee — Discussion on oblivious message retrieval

## License

MIT
