---
eip: XXXX
title: Post-Quantum Key Exchange for Stealth Addresses
description: Extension of ERC-5564/6538 for ML-KEM-based stealth addresses with viewing/spending separation, plus an optional pairwise channel optimization.
author: NN (@namnc)
discussions-to: https://ethereum-magicians.org/t/erc-xxxx-pq-key-exchange-stealth-addresses
status: Draft
type: Standards Track
category: ERC
created: 2026-04-03
requires: 5564, 6538
---

## Abstract

This ERC extends ERC-5564 (Stealth Addresses) and ERC-6538 (Stealth Meta-Address Registry) with post-quantum key material. It standardizes:

1. A key registry for PQ stealth meta-addresses (classical spending key + ML-KEM viewing key)
2. A direct ML-KEM stealth address protocol preserving viewing/spending separation via EC scalar addition
3. An optional pairwise channel optimization that amortizes the ML-KEM ciphertext overhead

The core insight: replace ECDH with ML-KEM for shared secret computation, but keep EC scalar addition (`stealth_sk = spending_sk + hash(ss)`) for stealth key derivation. This preserves the classical security model where a viewing key holder can detect payments but cannot spend.

## Motivation

ERC-5564 stealth addresses rely on ECDH, which is broken by quantum computers via Shor's algorithm. Stealth address announcements already on-chain are vulnerable to harvest-now-decrypt-later (HNDL).

ML-KEM (FIPS 203) is a drop-in replacement for ECDH as a shared secret source. The existing ERC-5564 stealth key derivation (EC scalar addition) works unchanged with ML-KEM. This ERC standardizes the replacement: the ML-KEM ciphertext (1,088 B) replaces the ECDH ephemeral key (33 B), and an optional pairwise channel optimization amortizes this to a one-time cost.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

### Definitions

- **Viewing key**: ML-KEM-768 decapsulation key. Used to compute shared secrets for payment detection. Safe to delegate.
- **Spending key**: secp256k1 private key. Used to derive stealth private keys and sign transactions. MUST remain private.
- **Stealth public key**: `spending_pk + hash(shared_secret) * G`. Computable by anyone with the shared secret and spending public key.
- **Stealth private key**: `spending_sk + hash(shared_secret)`. Computable only by the spending key holder.
- **View tag**: `SHA-256("pq-sa-view-tag-v1" || shared_secret)[0]`. A 1-byte tag that filters 99.6% of non-matching announcements.
- **Confirm tag**: `SHA-256("pq-sa-confirm-v1" || k_pairwise || nonce)[0..8]`. An 8-byte tag for channel authentication (1/2^64 false positive rate). Used during recovery to distinguish genuine channels from implicit-rejection artifacts.
- **Pairwise key**: A shared symmetric key established via hybrid KEM (ECDH + ML-KEM) during first contact.

### Interface

The reference implementation uses a pairwise hybrid KEM model (ECDH + ML-KEM-768). The interface matches the deployed `MemoRegistry` contract.

```solidity
// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// @title IERC_XXXX_MemoRegistry
/// @notice Discovery log for PQ stealth addresses with pairwise channels.
interface IERC_XXXX_MemoRegistry {

    /// @notice Emitted when a recipient registers their stealth meta-address.
    /// @param registrant The registering address
    /// @param spendingPk Spending public key (33 B compressed secp256k1)
    /// @param viewingPkEc EC viewing public key for hybrid KEM ECDH (33 B, separate from spending)
    /// @param viewingEk PQ viewing encapsulation key (1,184 B ML-KEM-768)
    event KeyRegistered(
        address indexed registrant,
        bytes spendingPk,
        bytes viewingPkEc,
        bytes viewingEk
    );

    /// @notice Emitted for hybrid KEM first contact (one-time per sender-recipient pair).
    event FirstContact(
        uint64 indexed memoId,
        uint256 indexed epoch,
        bytes payload
    );

    /// @notice Emitted for each subsequent stealth address payment.
    event Memo(
        uint64 indexed memoId,
        uint256 indexed epoch,
        bytes16 nonce,
        uint8 viewTag,
        bytes8 confirmTag
    );

    /// @notice Register a PQ stealth meta-address (3 keys).
    function registerKeys(
        bytes calldata spendingPk,
        bytes calldata viewingPkEc,
        bytes calldata viewingEk
    ) external;

    /// @notice Post a hybrid KEM first contact (1,121 B = 33 EPK + 1,088 ML-KEM ct).
    function postFirstContact(bytes calldata payload) external;

    /// @notice Post a pairwise memo (nonce + view tag + confirm tag).
    function postMemo(bytes16 nonce, uint8 viewTag, bytes8 confirmTag) external;
}
```

### Stealth Address Derivation

For all schemes, the stealth address MUST be derived using EC scalar addition:

```
shared_secret = KEM.Decapsulate(dk_kem, ciphertext)       // or SHA-256("pq-sa-pairwise-stealth-v1" || k_pairwise || nonce)
scalar = SHA-256("pq-sa-stealth-derive-v1" || shared_secret)
stealth_pk = spending_pk + scalar * G
stealth_sk = spending_sk + scalar                         // recipient only
stealth_addr = keccak256(stealth_pk)[12..32]
view_tag = SHA-256("pq-sa-view-tag-v1" || shared_secret)[0]
confirm_tag = SHA-256("pq-sa-confirm-v1" || k_pairwise || nonce)[0..8]   // pairwise mode only
```

This derivation MUST be used for both direct ML-KEM and pairwise modes. The only difference is how `shared_secret` is obtained.

### View Tag

The view tag is REQUIRED for all announcements. It is the first byte of `SHA-256("pq-sa-view-tag-v1" || shared_secret)`. Recipients SHOULD check the view tag before performing full stealth address derivation, filtering ~99.6% of non-matching announcements.

### Confirm Tag

The confirm tag is REQUIRED for pairwise channel memos. It is the first 8 bytes of `SHA-256("pq-sa-confirm-v1" || k_pairwise || nonce)`. The confirm tag provides channel authentication with a 1/2^64 false positive rate. Recipients SHOULD use a two-stage filter: check the view tag first (99.6% prefilter), then verify the confirm tag on surviving candidates. During wallet recovery, the confirm tag distinguishes genuine channels from implicit-rejection artifacts — an attacker can cover all 256 view tag values but cannot feasibly cover 2^64 confirm tag values, resisting memo-poisoning attacks.

### Pairwise Channel (OPTIONAL)

The first payment to a recipient uses a full hybrid KEM first contact (ECDH + ML-KEM-768). Subsequent payments reuse the established `k_pairwise`:

```
First contact:  shared_secret from hybrid KEM decapsulation
Subsequent:     shared_secret = SHA-256("pq-sa-pairwise-stealth-v1" || k_pairwise || nonce)
```

Subsequent payments emit `Memo` events (16 B nonce + 1 B view tag + 8 B confirm tag) instead of full `Announcement` events, reducing calldata from 1,089 B to 25 B per payment.

## Rationale

### Why EC scalar addition?

EC scalar addition (`stealth_sk = spending_sk + hash(ss)`) is the same derivation used by classical ERC-5564. It works with any shared secret source — ECDH or ML-KEM — because it only requires a 32-byte shared secret as input. The stealth key derivation is independent of the KEM used to produce the shared secret.

### Why pairwise channels as optional?

Direct ML-KEM stealth works without pairwise channels — 1,088 B per announcement. Pairwise channels are an optimization for active sender-recipient pairs, reducing per-payment calldata from 1,089 B to 25 B. The reference implementation demonstrates the pairwise model.

### Why not full PQ spending?

Stealth addresses use secp256k1 for transaction signing. Full PQ spending requires PQ signature schemes at the Ethereum protocol level (e.g., EIP-7932). This ERC focuses on the key exchange and discovery layer, which can be upgraded to PQ independently.

## Backwards Compatibility

This ERC is designed to coexist with ERC-5564 and ERC-6538. A wallet MAY register both classical and PQ meta-addresses simultaneously. The `MemoRegistry` contract is a separate deployment from the existing `ERC5564Announcer`.

## Reference Implementation

A reference implementation is available at [pq_SA](https://github.com/namnc/pq_SA):

- `primitives/src/stealth.rs` — EC algebra stealth derivation (Model 1 + 2)
- `primitives/src/hybrid_kem.rs` — ECDH + ML-KEM-768 hybrid KEM with separate viewing/spending keys
- `contracts/src/MemoRegistry.sol` — Pairwise channel memo log
- 45 tests (30 Rust + 15 Foundry), including delegation safety, nonce counter, secret zeroization, and confirm tag verification
- End-to-end Anvil demo: first contact → memo → ETH to stealth address → recipient detects and can spend

## Security Considerations

### Viewing/spending separation

The viewing key (`dk_kem`, ML-KEM decapsulation key) allows computing shared secrets and detecting payments. It does NOT allow spending. The spending key (`spending_sk`, secp256k1) is required to derive `stealth_sk = spending_sk + hash(ss)`. This separation is identical to ERC-5564's classical model.

### Quantum security scope

ML-KEM-768 provides NIST Level 3 post-quantum security for the key exchange. Stealth address spending uses secp256k1 ECDSA, which is quantum-vulnerable. A quantum attacker who can break secp256k1 could spend from stealth addresses whose public keys are visible on-chain. Mitigation: recipients should sweep stealth addresses promptly.

### Key sizes

ML-KEM-768 encapsulation keys are 1,184 bytes — stored on-chain in the `KeyRegistered` event. This is public information. The decapsulation key (2,400 bytes) is the viewing key and MUST be kept confidential (or shared only with trusted scanning servers).

### Harvest-now-decrypt-later (HNDL)

Classical ERC-5564 announcements contain ECDH ephemeral keys. An adversary recording these today can break them with a future quantum computer, linking stealth addresses to recipients. The hybrid KEM replaces ECDH with ECDH + ML-KEM-768, making harvested ciphertexts useless to a quantum attacker. `k_pairwise = HKDF(ss_ec || ss_kem || epk, "pq-sa-v1")` — the attacker must break both shared secrets, and ML-KEM-768 is quantum-resistant.

### Wallet recovery

Recipients SHOULD derive all keys deterministically from a single seed. First contact ciphertexts are stored permanently on-chain in events. A recipient who loses their device can re-derive keys from the seed, scan `FirstContact` or `Announcement` events, and decapsulate each ciphertext to obtain candidate pairwise keys. Due to ML-KEM implicit rejection, decapsulation always returns a key — even for first contacts not addressed to this recipient. Genuine channels MUST be verified using a two-stage filter on subsequent `Memo` events: first the view tag (1 byte, 99.6% rejection), then the confirm tag (`SHA-256("pq-sa-confirm-v1" || k_pairwise || nonce)[0..8]`, 1/2^64 false positive rate). The confirm tag authenticates the channel, resisting memo-poisoning attacks where an attacker covers all 256 view tag values.

The viewing/spending separation enables hardware wallet integration: `spending_sk` stays on the hardware device while `dk_kem` is exported to software wallets for scanning. To spend from a stealth address, the software wallet sends `scalar = hash(shared_secret)` to the hardware wallet, which computes `stealth_sk = spending_sk + scalar` and signs. The hardware wallet SHOULD verify that `spending_pk + scalar * G` matches the expected stealth address before signing.

### View tag privacy

The view tag leaks 1 bit of information per announcement (whether the tag matches). Over many announcements, this could help narrow down the recipient. This is identical to ERC-5564's existing view tag privacy model.

## Copyright

Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).
