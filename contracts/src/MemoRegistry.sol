// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title MemoRegistry — Lightweight discovery log for PQ stealth addresses
/// @notice Logs first-contact KEM data and per-payment memos for note discovery.
///         Value transfer happens via direct ETH/token sends to derived stealth
///         addresses — no nullifiers, no ZK proofs, no on-chain spend function.
///         Spending is Ethereum-native (secp256k1 signature from stealth address).
///
///         NOTE: Stealth addresses use classical secp256k1. For full PQ spending,
///         Ethereum needs PQ signatures (EIP-7932). Our scope is PQ KEM optimization.
contract MemoRegistry {
    uint64 public nextMemoId;
    uint256 public currentEpoch;
    uint256 public epochStartBlock;
    uint256 public constant BLOCKS_PER_EPOCH = 7200;

    address public immutable owner;
    uint256 public minPostFee;

    mapping(address => bool) public registered;

    // --- Events ---

    /// @notice First contact: establishes a pairwise channel via hybrid KEM.
    event FirstContact(
        uint64 indexed memoId,
        uint256 indexed epoch,
        bytes payload  // epk(33) + ct_pq(1088) + nonce(16) + optional encrypted memo
    );

    /// @notice Per-payment memo: nonce for stealth address derivation + optional PVW clue.
    ///         The actual value transfer is a separate ETH/token send to the derived address.
    event Memo(
        uint64 indexed memoId,
        uint256 indexed epoch,
        bytes16 nonce,
        bytes pvwClue  // empty if no OMR, or 52 B PVW clue for OMR discovery
    );

    /// @notice Recipient registers PQ public keys for first-contact discovery.
    event KeyRegistered(
        address indexed recipient,
        bytes pkEc,
        bytes ekKem
    );

    constructor() {
        owner = msg.sender;
        epochStartBlock = block.number;
    }

    // =========================================================================
    //  Key registration
    // =========================================================================

    function registerKeys(bytes calldata pkEc, bytes calldata ekKem) external {
        require(pkEc.length == 33, "pkEc must be 33 bytes");
        require(ekKem.length == 1184, "ekKem must be 1184 bytes");
        registered[msg.sender] = true;
        emit KeyRegistered(msg.sender, pkEc, ekKem);
    }

    // =========================================================================
    //  First contact (one-time per sender-recipient pair)
    // =========================================================================

    function postFirstContact(bytes calldata payload) external payable {
        require(msg.value >= minPostFee, "below min fee");
        _advanceEpoch();
        emit FirstContact(nextMemoId++, currentEpoch, payload);
    }

    // =========================================================================
    //  Per-payment memo (nonce + optional PVW clue for OMR)
    // =========================================================================

    /// @notice Post a memo for a payment. The nonce is used by the recipient to
    ///         derive the stealth address where funds were sent.
    /// @param nonce 16-byte nonce for stealth address derivation
    /// @param pvwClue Optional PVW detection clue (52 B for OMR, or empty)
    function postMemo(bytes16 nonce, bytes calldata pvwClue) external payable {
        require(msg.value >= minPostFee, "below min fee");
        if (pvwClue.length > 0) {
            require(pvwClue.length == 52, "pvwClue must be 52 bytes if provided");
        }
        _advanceEpoch();
        emit Memo(nextMemoId++, currentEpoch, nonce, pvwClue);
    }

    // =========================================================================
    //  Admin
    // =========================================================================

    function setMinPostFee(uint256 _fee) external {
        require(msg.sender == owner, "not owner");
        minPostFee = _fee;
    }

    // =========================================================================
    //  Internal
    // =========================================================================

    function _advanceEpoch() internal {
        while (block.number >= epochStartBlock + BLOCKS_PER_EPOCH) {
            currentEpoch++;
            epochStartBlock += BLOCKS_PER_EPOCH;
        }
    }
}
