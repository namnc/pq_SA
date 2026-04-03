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

ERC-5564 stealth addresses rely on ECDH, which is broken by quantum computers. ML-KEM (FIPS 203) provides post-quantum key encapsulation, but previous PQ stealth proposals (e.g., SPECTER) lose viewing/spending separation by deriving `stealth_sk = hash(ss || spending_pk)` — since `spending_pk` is public, the viewing key holder can spend.

This ERC preserves the separation by using EC scalar addition for the stealth key derivation, identical to the classical ERC-5564 approach. The ML-KEM ciphertext (1,088 B) replaces the ECDH ephemeral key (33 B) — an optional pairwise channel optimization amortizes this to a one-time cost.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

### Definitions

- **Viewing key**: ML-KEM-768 decapsulation key. Used to compute shared secrets for payment detection. Safe to delegate.
- **Spending key**: secp256k1 private key. Used to derive stealth private keys and sign transactions. MUST remain private.
- **Stealth public key**: `spending_pk + hash(shared_secret) * G`. Computable by anyone with the shared secret and spending public key.
- **Stealth private key**: `spending_sk + hash(shared_secret)`. Computable only by the spending key holder.
- **View tag**: `hash(shared_secret)[0]`. A 1-byte tag that filters 99.6% of non-matching announcements.
- **Pairwise key**: A shared symmetric key established via hybrid KEM (ECDH + ML-KEM) during first contact.

### Scheme IDs

| Scheme ID | Key exchange | Stealth derivation | Ciphertext size |
|-----------|-------------|-------------------|-----------------|
| 0x01 | ECDH (secp256k1) | EC scalar addition | 33 B (classical, existing ERC-5564) |
| 0x02 | ML-KEM-768 | EC scalar addition | 1,088 B (direct PQ replacement) |
| 0x03 | ECDH + ML-KEM-768 hybrid | EC scalar addition | 1,121 B (first contact only) |

Scheme 0x02 is the direct PQ replacement. Scheme 0x03 adds transitional ECDH security and enables pairwise channel optimization.

### Interface

```solidity
// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// @title IERC_XXXX_KeyRegistry
/// @notice Registry for PQ stealth meta-addresses.
interface IERC_XXXX_KeyRegistry {

    /// @notice Emitted when a recipient registers their stealth meta-address.
    /// @param registrant The registering address
    /// @param schemeId Cryptographic scheme identifier
    /// @param spendingPk Classical spending public key (33 B compressed secp256k1)
    /// @param viewingEk PQ viewing encapsulation key (1,184 B for ML-KEM-768)
    event KeysRegistered(
        address indexed registrant,
        uint8 indexed schemeId,
        bytes spendingPk,
        bytes viewingEk
    );

    /// @notice Register a PQ stealth meta-address.
    function registerKeys(
        uint8 schemeId,
        bytes calldata spendingPk,
        bytes calldata viewingEk
    ) external;
}

/// @title IERC_XXXX_Announcer
/// @notice Announces stealth address payments for recipient discovery.
interface IERC_XXXX_Announcer {

    /// @notice Emitted for each stealth address payment.
    /// @param schemeId Cryptographic scheme used
    /// @param kemCiphertext ML-KEM ciphertext (1,088 B for scheme 0x02) or
    ///        first-contact payload (1,121 B for scheme 0x03, empty for subsequent)
    /// @param viewTag 1-byte view tag for fast filtering
    event Announcement(
        uint8 indexed schemeId,
        bytes kemCiphertext,
        uint8 viewTag
    );

    /// @notice For scheme 0x03 pairwise: memo for subsequent payments
    ///         (nonce only, no KEM ciphertext).
    event Memo(
        uint64 indexed memoId,
        bytes16 nonce,
        uint8 viewTag
    );

    /// @notice Announce a stealth address payment (scheme 0x02: direct ML-KEM).
    function announce(
        uint8 schemeId,
        bytes calldata kemCiphertext,
        uint8 viewTag
    ) external payable;

    /// @notice Post a pairwise memo (scheme 0x03: after first contact).
    function postMemo(
        bytes16 nonce,
        uint8 viewTag
    ) external payable;
}
```

### Stealth Address Derivation

For all schemes, the stealth address MUST be derived using EC scalar addition:

```
shared_secret = KEM.Decapsulate(viewing_dk, ciphertext)   // or HKDF(k_pairwise, nonce)
scalar = SHA-256("pq-sa-stealth-derive-v1" || shared_secret)
stealth_pk = spending_pk + scalar * G
stealth_sk = spending_sk + scalar                         // recipient only
stealth_addr = keccak256(stealth_pk)[12..32]
view_tag = SHA-256("pq-sa-view-tag-v1" || shared_secret)[0]
```

This derivation MUST be used for all scheme IDs. The only difference between schemes is how `shared_secret` is obtained.

### View Tag

The view tag is REQUIRED for all announcements. It is the first byte of `SHA-256("pq-sa-view-tag-v1" || shared_secret)`. Recipients SHOULD check the view tag before performing full stealth address derivation, filtering ~99.6% of non-matching announcements.

### Pairwise Channel (Scheme 0x03, OPTIONAL)

For scheme 0x03, the first payment to a recipient uses a full hybrid KEM first contact (ECDH + ML-KEM-768). Subsequent payments reuse the established `k_pairwise`:

```
First contact:  shared_secret from hybrid KEM decapsulation
Subsequent:     shared_secret = HKDF-SHA256(k_pairwise || nonce, "pq-sa-pairwise-stealth-v1")
```

Subsequent payments emit `Memo` events (16 B nonce + 1 B view tag) instead of full `Announcement` events, reducing calldata from 1,089 B to 17 B per payment.

## Rationale

### Why EC scalar addition?

ML-KEM is a KEM, not a Diffie-Hellman protocol. It produces a shared secret but has no algebraic structure for key derivation. By using EC scalar addition for the stealth key (`stealth_sk = spending_sk + hash(ss)`), we:

1. **Preserve viewing/spending separation**: the viewing key holder computes `hash(ss)` but not `spending_sk`
2. **Reuse ERC-5564's proven security model**: the derivation is identical, only the shared secret source changes
3. **Keep Ethereum-native spending**: stealth addresses are secp256k1 addresses, signed normally

Alternative approaches like `stealth_sk = hash(ss || spending_pk)` (used by SPECTER) break viewing/spending separation because `spending_pk` is public.

### Why pairwise channels as optional?

Direct ML-KEM stealth (scheme 0x02) works without pairwise channels — 1,088 B per announcement. Pairwise channels (scheme 0x03) are an optimization for active sender-recipient pairs, reducing per-payment calldata from 1,089 B to 17 B.

The optimization is economically significant (32x calldata reduction) but not architecturally necessary. Wallets SHOULD implement scheme 0x02 first, then add scheme 0x03 support for frequent counterparties.

### Why not full PQ spending?

Stealth addresses use secp256k1 for transaction signing. Full PQ spending requires PQ signature schemes at the Ethereum protocol level (e.g., EIP-7932). This ERC focuses on the key exchange and discovery layer, which can be upgraded to PQ independently.

## Backwards Compatibility

This ERC is designed to coexist with ERC-5564 and ERC-6538:

- Scheme 0x01 IS classical ERC-5564. Existing wallets continue to work.
- Schemes 0x02/0x03 add PQ alternatives without breaking existing functionality.
- A wallet MAY register both classical (scheme 0x01) and PQ (scheme 0x02/0x03) meta-addresses simultaneously.
- The `ERC5564Announcer` contract at `0x55649E01B5Df198D18D95b5cc5051630cfD45564` can be reused for scheme 0x02 announcements (the `kemCiphertext` field replaces `ephemeralPubKey`).

## Reference Implementation

A reference implementation is available at [pq_SA](https://github.com/namnc/pq_SA):

- `primitives/src/stealth.rs` — EC algebra stealth derivation (Model 1 + 2), 8 tests
- `primitives/src/hybrid_kem.rs` — ECDH + ML-KEM-768 hybrid KEM
- `contracts/src/MemoRegistry.sol` — Pairwise channel memo log, 11 Foundry tests
- End-to-end Anvil demo: first contact → memo → ETH to stealth address → recipient detects and can spend

## Security Considerations

### Viewing/spending separation

The viewing key (`viewing_dk`, ML-KEM decapsulation key) allows computing shared secrets and detecting payments. It does NOT allow spending. The spending key (`spending_sk`, secp256k1) is required to derive `stealth_sk = spending_sk + hash(ss)`. This separation is identical to ERC-5564's classical model.

### Quantum security scope

ML-KEM-768 provides NIST Level 3 post-quantum security for the key exchange. Stealth address spending uses secp256k1 ECDSA, which is quantum-vulnerable. A quantum attacker who can break secp256k1 could spend from stealth addresses whose public keys are visible on-chain. Mitigation: recipients should sweep stealth addresses promptly.

### Key sizes

ML-KEM-768 encapsulation keys are 1,184 bytes — stored on-chain in the `KeysRegistered` event. This is public information. The decapsulation key (2,400 bytes) is the viewing key and MUST be kept confidential (or shared only with trusted scanning servers).

### View tag privacy

The view tag leaks 1 bit of information per announcement (whether the tag matches). Over many announcements, this could help narrow down the recipient. This is identical to ERC-5564's existing view tag privacy model.

## Copyright

Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).
