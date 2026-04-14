// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title MemoRegistry — Discovery log for PQ stealth addresses
/// @notice Logs first-contact KEM data and per-payment memos for stealth address discovery.
///         Value transfer happens via direct ETH/token sends to derived stealth addresses.
///         No fees, no nullifiers, no spending logic. Gas is the only cost.
contract MemoRegistry {
    uint64 public nextMemoId;
    uint256 public currentEpoch;
    uint256 public epochStartBlock;
    uint256 public constant BLOCKS_PER_EPOCH = 7200;

    mapping(address => bool) public registered;

    event FirstContact(
        uint64 indexed memoId,
        uint256 indexed epoch,
        bytes payload
    );

    event Memo(
        uint64 indexed memoId,
        uint256 indexed epoch,
        bytes16 nonce,
        uint8 viewTag,
        bytes4 confirmTag
    );

    event KeyRegistered(
        address indexed recipient,
        bytes spendingPk,
        bytes viewingPkEc,
        bytes viewingEk
    );

    constructor() {
        epochStartBlock = block.number;
    }

    function registerKeys(
        bytes calldata spendingPk,
        bytes calldata viewingPkEc,
        bytes calldata viewingEk
    ) external {
        require(spendingPk.length == 33, "spendingPk must be 33 bytes");
        require(viewingPkEc.length == 33, "viewingPkEc must be 33 bytes");
        require(viewingEk.length == 1184, "viewingEk must be 1184 bytes");
        require(keccak256(spendingPk) != keccak256(viewingPkEc), "spending and viewing EC keys must differ");
        registered[msg.sender] = true;
        emit KeyRegistered(msg.sender, spendingPk, viewingPkEc, viewingEk);
    }

    function postFirstContact(bytes calldata payload) external {
        require(payload.length == 1121, "payload must be 1121 bytes (33 EPK + 1088 KEM ct)");
        _advanceEpoch();
        emit FirstContact(nextMemoId++, currentEpoch, payload);
    }

    function postMemo(bytes16 nonce, uint8 viewTag, bytes4 confirmTag) external {
        _advanceEpoch();
        emit Memo(nextMemoId++, currentEpoch, nonce, viewTag, confirmTag);
    }

    function _advanceEpoch() internal {
        uint256 elapsed = block.number - epochStartBlock;
        if (elapsed >= BLOCKS_PER_EPOCH) {
            uint256 skip = elapsed / BLOCKS_PER_EPOCH;
            currentEpoch += skip;
            epochStartBlock += skip * BLOCKS_PER_EPOCH;
        }
    }
}
