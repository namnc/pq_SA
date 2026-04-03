---
eip: XXXX
title: Post-Quantum Private Note Registry with Pairwise Channels
description: Interface for PQ-safe private note encryption, pairwise channel establishment, and server-incentivized note discovery on Ethereum.
author: NN (@nn)
discussions-to: https://ethereum-magicians.org/t/erc-xxxx-pq-private-note-registry
status: Draft
type: Standards Track
category: ERC
created: 2026-04-03
requires: 5564, 6538
---

## Abstract

This ERC defines an interface for **post-quantum private note encryption and discovery** on Ethereum. It standardizes:

1. A key registry for hybrid PQ key material (classical EC + ML-KEM)
2. A two-phase note posting protocol: first-contact (KEM ciphertext) and known-pair (symmetric-only)
3. A subscription and pay-on-spend model for server-incentivized note archival and oblivious message retrieval

Unlike ERC-5564/6538 stealth addresses which derive one-time addresses via ECDH, this standard uses **persistent pairwise channels** — an architectural necessity for post-quantum KEM schemes that lack read-only (viewing) key subsets.

## Motivation

Current privacy standards on Ethereum (ERC-5564 stealth addresses, ERC-6538 stealth meta-address registry) rely on ECDH, which is broken by quantum computers. ML-KEM (FIPS 203) provides post-quantum key encapsulation, but introduces a structural constraint: **the decapsulation key is the full secret**. There is no way to derive a read-only viewing key from the private key.

This means:

- **Stealth addresses don't work with ML-KEM.** The recipient cannot delegate scanning to a viewer without giving away the ability to spend.
- **Pairwise channels become necessary.** Once a sender and recipient establish a shared symmetric key, subsequent notes use only symmetric encryption (ChaCha20-Poly1305). The expensive KEM operation (1,088 B ciphertext) happens once per sender-recipient pair, not per note.
- **Server-assisted discovery is needed.** Without viewing keys, oblivious message retrieval (OMR) with homomorphic encryption becomes the practical path for scalable note discovery.

This ERC standardizes the on-chain interface so that:
- Wallets can register PQ keys in a canonical format
- Applications can post and discover private notes interoperably
- OMR servers can index notes and serve recipients without learning note contents
- Payment for archival and discovery is flexible (sender-pays, receiver-pays, subscription)

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

### Definitions

- **First contact**: The initial note between a sender-recipient pair. Contains a KEM ciphertext that establishes a shared symmetric key (pairwise key).
- **Known-pair note**: A subsequent note on an established pairwise channel. Contains only symmetric ciphertext — no KEM material.
- **Pairwise key**: A shared symmetric key derived from a hybrid KEM (e.g., ECDH + ML-KEM, combined via HKDF).
- **Commitment**: A binding hash of the note plaintext (e.g., SHA-256 or Poseidon).
- **Nullifier**: A value derived from the pairwise key and note nonce, revealed when spending to prevent double-spend.
- **Scheme ID**: A byte identifying the cryptographic suite (key types, KEM algorithm, AEAD).

### Scheme IDs

| Scheme ID | Classical | PQ KEM | AEAD | Key sizes |
|-----------|-----------|--------|------|-----------|
| 0x01 | secp256k1 ECDH | ML-KEM-768 | ChaCha20-Poly1305 | pkEc: 33 B, ekKem: 1184 B |
| 0x02 | secp256k1 ECDH | ML-KEM-1024 | ChaCha20-Poly1305 | pkEc: 33 B, ekKem: 1568 B |
| 0x03 | (reserved) | (reserved) | (reserved) | future PQ algorithms |

Implementers MAY define additional scheme IDs. Scheme ID 0x00 is reserved.

### Interface

```solidity
// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// @title IERC_XXXX_KeyRegistry
/// @notice Registry for post-quantum key material.
interface IERC_XXXX_KeyRegistry {

    /// @notice Emitted when a recipient registers their public keys.
    /// @param registrant The address that registered keys
    /// @param schemeId Cryptographic scheme identifier
    /// @param pkClassical Classical public key (e.g., 33 B compressed secp256k1)
    /// @param ekPQ Post-quantum encapsulation key (e.g., 1184 B ML-KEM-768)
    event KeysRegistered(
        address indexed registrant,
        uint8 indexed schemeId,
        bytes pkClassical,
        bytes ekPQ
    );

    /// @notice Register public keys for a given scheme.
    /// @param schemeId Cryptographic scheme identifier
    /// @param pkClassical Classical public key bytes
    /// @param ekPQ Post-quantum encapsulation key bytes
    function registerKeys(
        uint8 schemeId,
        bytes calldata pkClassical,
        bytes calldata ekPQ
    ) external;

    /// @notice Register keys on behalf of another address (with signature).
    /// @param registrant The address to register for
    /// @param schemeId Cryptographic scheme identifier
    /// @param pkClassical Classical public key bytes
    /// @param ekPQ Post-quantum encapsulation key bytes
    /// @param signature EIP-712 or EIP-1271 signature from registrant
    function registerKeysOnBehalf(
        address registrant,
        uint8 schemeId,
        bytes calldata pkClassical,
        bytes calldata ekPQ,
        bytes calldata signature
    ) external;
}

/// @title IERC_XXXX_NoteRegistry
/// @notice Registry for posting and discovering private notes via pairwise channels.
interface IERC_XXXX_NoteRegistry {

    /// @notice Emitted when a sender initiates a new pairwise channel.
    /// @param noteId Sequential note identifier
    /// @param epoch Current epoch
    /// @param schemeId Cryptographic scheme used
    /// @param commitment Binding hash of the note plaintext
    /// @param payload Packed first-contact data (ephemeral key + KEM ciphertext + nonce + AEAD ciphertext)
    event FirstContact(
        uint64 indexed noteId,
        uint256 indexed epoch,
        uint8 indexed schemeId,
        bytes32 commitment,
        bytes payload
    );

    /// @notice Emitted for notes on an established pairwise channel.
    /// @param noteId Sequential note identifier
    /// @param epoch Current epoch
    /// @param commitment Binding hash of the note plaintext
    /// @param nonce AEAD nonce
    /// @param ciphertext Encrypted note data
    event NotePosted(
        uint64 indexed noteId,
        uint256 indexed epoch,
        bytes32 commitment,
        bytes16 nonce,
        bytes ciphertext
    );

    /// @notice Post a first-contact message to initiate a pairwise channel.
    /// @param schemeId Cryptographic scheme identifier
    /// @param commitment Note commitment hash
    /// @param payload Packed first-contact data
    function postFirstContact(
        uint8 schemeId,
        bytes32 commitment,
        bytes calldata payload
    ) external payable;

    /// @notice Post a note on an established pairwise channel.
    /// @param commitment Note commitment hash
    /// @param nonce AEAD nonce (16 bytes)
    /// @param ciphertext Encrypted note data
    function postNote(
        bytes32 commitment,
        bytes16 nonce,
        bytes calldata ciphertext
    ) external payable;
}

/// @title IERC_XXXX_Incentives
/// @notice Subscription and pay-on-spend model for server-incentivized note services.
interface IERC_XXXX_Incentives {

    event BalanceDeposited(address indexed account, uint256 amount);
    event BalanceWithdrawn(address indexed account, uint256 amount);
    event NoteSpent(uint64 indexed noteId, bytes32 nullifier, uint256 feePaid);

    /// @notice Deposit ETH as subscription balance for archival and OMR services.
    function depositBalance() external payable;

    /// @notice Withdraw unused subscription balance.
    /// @param amount Amount to withdraw in wei
    function withdrawBalance(uint256 amount) external;

    /// @notice Spend (nullify) a note. Deducts the server fee from the caller's
    ///         balance and forwards it to the service provider.
    /// @param noteId The note being spent
    /// @param nullifier The nullifier (derived from pairwise key + nonce, prevents double-spend)
    function spendNote(uint64 noteId, bytes32 nullifier) external;

    /// @notice Query subscription balance.
    /// @param account Address to query
    /// @return balance Current balance in wei
    function balanceOf(address account) external view returns (uint256 balance);
}
```

### First-Contact Payload Format

The `payload` parameter in `postFirstContact` MUST be encoded as:

```
payload = ephemeralKey || kemCiphertext || nonce || aeadCiphertext
```

| Field | Scheme 0x01 size | Description |
|-------|-----------------|-------------|
| `ephemeralKey` | 33 B | Compressed secp256k1 ephemeral public key |
| `kemCiphertext` | 1,088 B | ML-KEM-768 ciphertext |
| `nonce` | 16 B | AEAD nonce |
| `aeadCiphertext` | variable | ChaCha20-Poly1305 encrypted note |

### Epoch Semantics

Implementations SHOULD track epochs for OMR digest boundaries. An epoch is RECOMMENDED to be 7,200 blocks (~1 day on mainnet). The epoch counter MUST be monotonically increasing and MUST be included in the `FirstContact` and `NotePosted` events.

### Nullifier Derivation

The nullifier MUST be derived deterministically from the pairwise key and note nonce to ensure double-spend prevention. The RECOMMENDED derivation is:

```
nullifier = SHA-256("nullifier" || k_pairwise || nonce)
```

The registry MUST reject a `spendNote` call if the nullifier has already been recorded.

### Optional Extensions

#### Archival Fee (OPTIONAL)

If `msg.value > 0` is included with `postFirstContact` or `postNote`, the implementation SHOULD forward the fee to a configured archival service address. This enables sender-pays blob persistence beyond the EIP-4844 pruning window.

#### OMR Detection Clue (OPTIONAL)

For OMR-enabled deployments, `postNote` MAY accept an additional `pvwClue` parameter (56 B PVW detection tag) for oblivious message retrieval. This is left to future extension or a companion ERC.

## Rationale

### Why not extend ERC-5564/6538?

ERC-5564 stealth addresses derive one-time addresses via ECDH shared secrets. This fundamentally requires a viewing key — a key that can compute shared secrets but not spend. ML-KEM has no such key. The pairwise channel model is architecturally different: it establishes a long-lived symmetric relationship rather than deriving per-transaction addresses.

ERC-6538's registry stores stealth meta-addresses (spending + viewing public keys). Our registry stores hybrid PQ key material that is 18x larger (1,217 B vs ~66 B) and serves a different purpose (KEM encapsulation vs ECDH derivation).

### Why pairwise channels?

BIP-47 (2015) proposed pairwise payment codes for Bitcoin — the same pattern. It was largely abandoned classically because: (1) the 33 B ECDH ephemeral key is trivial, (2) 1-byte view tags filter 99.6% of non-matching notes, (3) viewing keys enable safe scanning delegation, and (4) stealth addresses provide full unlinkability without persistent state.

None of these hold for ML-KEM. The ciphertext is 1,088 B (33x larger), no view tag or viewing key exists (the decapsulation key is the full secret), and delegation requires giving away spending capability. Without pairwise channels, every PQ note repeats the 1,088 B ciphertext — a permanent 150% overhead.

Pairwise channels reduce the KEM overhead from per-note to per-channel: the 1,088 B appears once at first contact, then amortizes to 1,092/N bytes per note. At N>=39, PQ total calldata is less than classical. Steady-state known-pair notes (73.5K gas, 680 B) are 500 gas cheaper than classical ECDH (74K gas, 709 B) because the pairwise channel eliminated the 33 B per-note ephemeral key.

### Why two fees (sender + receiver)?

In a privacy system, the contract cannot distinguish legitimate notes from spam — any content-based filtering would leak information about the traffic. The system does not try to define or detect spam. Instead, every note pays its own processing cost via two complementary fees:

- **Sender fee** (non-refundable, at post time): Covers the OMR server's FHE processing cost per note. This makes posting self-funding regardless of whether the note is "legitimate" or "spam." The attacker's cost scales linearly with the attack volume, and the server can always add capacity funded by the attacker's own fees.

- **Spend fee** (deducted from recipient balance, at spend time): Covers long-term archival and retrieval. The recipient deposits a subscription balance upfront; the fee is deducted when nullifying a note.

A bond model (refundable if spent, forfeited if not) was considered and rejected: "unspent" is not equivalent to "spam" — legitimate notes may be slow to spend (recipient offline, small amounts, memo-only). The flat sender fee makes no such distinction.

### Why scheme IDs?

Post-quantum cryptography is evolving. ML-KEM-768 may be superseded by ML-KEM-1024, or by future algorithms. Scheme IDs allow the registry to support multiple key types simultaneously, enabling gradual migration without breaking existing channels.

## Backwards Compatibility

This ERC introduces new functionality and does not modify existing ERCs. It is designed to coexist with ERC-5564 and ERC-6538:

- A wallet MAY register both classical stealth meta-addresses (ERC-6538) and PQ keys (this ERC) simultaneously.
- A sender MAY use ERC-5564 stealth addresses for classical recipients and this ERC's pairwise channels for PQ recipients.
- The `schemeId` field prevents confusion between key types.

## Reference Implementation

A reference implementation is available at [pq-sa](https://github.com/namnc/pq-sa) with:

- `NoteRegistry.sol` — Solidity contract implementing all three interfaces (key registry, note posting, incentives)
- Rust cryptographic primitives (hybrid KEM, AEAD, erasure coding, commitments)
- End-to-end demo deployed on Sepolia at [`0x07EB0C4D70041D2B4CAC38cAB9bd2360d0639E6E`](https://sepolia.etherscan.io/address/0x07EB0C4D70041D2B4CAC38cAB9bd2360d0639E6E)
- 37 Rust tests + 22 Foundry tests

Scheme 0x01 (secp256k1 + ML-KEM-768 + ChaCha20-Poly1305) is fully implemented and tested.

## Security Considerations

### Hybrid security

The first-contact KEM combines ECDH and ML-KEM-768 via HKDF. If either primitive holds, the pairwise key is secure. This provides transitional security during the migration to post-quantum cryptography.

### Implicit rejection

ML-KEM decapsulation with the wrong key returns a pseudorandom shared secret (FIPS 203 implicit rejection). The AEAD decryption then fails with overwhelming probability. This prevents oracles — a wrong-recipient decapsulation is indistinguishable from random.

### Key size and on-chain exposure

ML-KEM-768 encapsulation keys are 1,184 bytes — stored on-chain in the `KeysRegistered` event. This is public information (encapsulation keys are meant to be public). The decapsulation key never appears on-chain.

### Nullifier privacy

The nullifier `SHA-256("nullifier" || k_pairwise || nonce)` is deterministic but unlinkable: without `k_pairwise`, the nullifier cannot be connected to the note it spends. However, the spend transaction reveals the nullifier and `noteId` together, which links them at spend time. This is inherent to any nullifier-based system.

### Subscription balance privacy

The `depositBalance` and `withdrawBalance` functions are called by the recipient's address, which may link deposits to spending patterns. Production deployments SHOULD use a relayer or ERC-4337 paymaster to decouple the recipient's identity from their subscription.

### PQ viewing keys (open problem)

ML-KEM has no read-only key subset. This means the recipient cannot delegate scanning without exposing their spending capability. Oblivious message retrieval (OMR) is the current mitigation — the server scans on behalf of the recipient under FHE, learning nothing. This is specified but not standardized in this ERC; a companion ERC for OMR interfaces is anticipated.

### Blob data availability

If note ciphertext is stored in EIP-4844 blobs (recommended for cost efficiency), it is pruned after ~18 days. The archival fee mechanism in `IERC_XXXX_Incentives` addresses this, but persistence depends on the archival service's reliability. On-chain commitments remain permanent regardless of blob availability.

## Copyright

Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).
