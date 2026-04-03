// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title NoteRegistry — Append-only log for PQ stealth address note distribution
/// @notice Stores first-contact KEM ciphertexts and encrypted notes as events.
///         All cryptographic verification happens off-chain on the recipient side.
///         Implements a two-fee model:
///         1. Sender fee: paid at post time, covers FHE processing (non-refundable)
///         2. Spend fee: deducted from recipient balance at spend time, covers archival
contract NoteRegistry {
    uint64 public nextNoteId;
    uint256 public currentEpoch;
    uint256 public epochStartBlock;
    uint256 public constant BLOCKS_PER_EPOCH = 7200; // ~1 day on mainnet

    /// @notice Contract owner (deployer). Manages admin functions.
    address public immutable owner;

    /// @notice Address that receives archival/OMR fees. Zero = disabled.
    address public archivalVault;

    /// @notice Minimum fee required when posting a note (spam prevention).
    uint256 public minSenderFee;

    /// @notice Fee deducted from recipient balance per note spend.
    uint256 public serverFeePerNote;

    /// @notice Recipient subscription balances.
    mapping(address => uint256) public balances;

    /// @notice Mapping from noteId to commitment.
    mapping(uint64 => bytes32) public noteCommitments;

    /// @notice Tracks whether a note has been archived.
    mapping(uint64 => bool) public archived;

    /// @notice Tracks whether a noteId has been spent.
    mapping(uint64 => bool) public spent;

    /// @notice Tracks nullifiers to prevent reuse across notes.
    mapping(bytes32 => bool) public nullifiers;

    mapping(address => bool) public registered;

    // --- Events ---

    event FirstContact(
        uint64 indexed noteId,
        uint256 indexed epoch,
        bytes32 commitment,
        bytes payload
    );

    event NotePosted(
        uint64 indexed noteId,
        uint256 indexed epoch,
        bytes32 commitment,
        bytes16 nonce,
        bytes ciphertext
    );

    event KeyRegistered(
        address indexed recipient,
        bytes pkEc,
        bytes ekKem
    );

    event NoteArchived(
        uint64 indexed noteId,
        bytes32 commitment,
        address payer,
        uint256 fee
    );

    event BalanceDeposited(address indexed account, uint256 amount);
    event BalanceWithdrawn(address indexed account, uint256 amount);
    event NoteSpent(uint64 indexed noteId, bytes32 nullifier, uint256 feePaid);

    constructor(address _archivalVault) {
        owner = msg.sender;
        epochStartBlock = block.number;
        archivalVault = _archivalVault;
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
    //  Note posting (sender fee enforced)
    // =========================================================================

    function postFirstContact(bytes32 commitment, bytes calldata payload) external payable {
        require(commitment != bytes32(0), "zero commitment");
        require(msg.value >= minSenderFee, "below min sender fee");
        _advanceEpoch();
        uint64 noteId = nextNoteId++;
        noteCommitments[noteId] = commitment;
        emit FirstContact(noteId, currentEpoch, commitment, payload);
        _handleFee(noteId, commitment);
    }

    function postNote(
        bytes32 commitment,
        bytes16 nonce,
        bytes calldata ciphertext
    ) external payable {
        require(commitment != bytes32(0), "zero commitment");
        require(msg.value >= minSenderFee, "below min sender fee");
        _advanceEpoch();
        uint64 noteId = nextNoteId++;
        noteCommitments[noteId] = commitment;
        emit NotePosted(noteId, currentEpoch, commitment, nonce, ciphertext);
        _handleFee(noteId, commitment);
    }

    // =========================================================================
    //  Receiver-pays archival (within blob window)
    // =========================================================================

    function archiveNote(uint64 noteId) external payable {
        require(noteCommitments[noteId] != bytes32(0), "note does not exist");
        require(!archived[noteId], "already archived");
        require(msg.value > 0, "must send archival fee");
        _handleFee(noteId, noteCommitments[noteId]);
    }

    // =========================================================================
    //  Subscription: deposit/withdraw balance
    // =========================================================================

    function depositBalance() external payable {
        require(msg.value > 0, "must send value");
        balances[msg.sender] += msg.value;
        emit BalanceDeposited(msg.sender, msg.value);
    }

    function withdrawBalance(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;
        (bool sent,) = msg.sender.call{value: amount}("");
        require(sent, "withdraw failed");
        emit BalanceWithdrawn(msg.sender, amount);
    }

    // =========================================================================
    //  Spend: nullifier bound to noteId, one spend per note
    // =========================================================================

    /// @notice Spend (nullify) a note. Each noteId can only be spent once.
    ///         The nullifier must be unique and is bound to the noteId.
    /// @param noteId The note being spent
    /// @param nullifier The nullifier (derived off-chain from k_pairwise + nonce).
    ///        The contract binds this nullifier to noteId to prevent reuse.
    function spendNote(uint64 noteId, bytes32 nullifier) external {
        require(noteCommitments[noteId] != bytes32(0), "note does not exist");
        require(!spent[noteId], "note already spent");
        require(!nullifiers[nullifier], "nullifier already used");

        spent[noteId] = true;
        nullifiers[nullifier] = true;

        uint256 fee = serverFeePerNote;
        if (fee > 0 && archivalVault != address(0)) {
            require(balances[msg.sender] >= fee, "insufficient balance for fee");
            balances[msg.sender] -= fee;
            (bool sent,) = archivalVault.call{value: fee}("");
            require(sent, "fee transfer failed");
        }

        emit NoteSpent(noteId, nullifier, fee);
    }

    // =========================================================================
    //  Admin (owner-only)
    // =========================================================================

    function setArchivalVault(address _archivalVault) external {
        require(msg.sender == owner, "not owner");
        archivalVault = _archivalVault;
    }

    function setServerFeePerNote(uint256 _fee) external {
        require(msg.sender == owner, "not owner");
        serverFeePerNote = _fee;
    }

    function setMinSenderFee(uint256 _fee) external {
        require(msg.sender == owner, "not owner");
        minSenderFee = _fee;
    }

    // =========================================================================
    //  Internal
    // =========================================================================

    function _handleFee(uint64 noteId, bytes32 commitment) internal {
        if (msg.value > 0) {
            if (archivalVault != address(0)) {
                archived[noteId] = true;
                (bool sent,) = archivalVault.call{value: msg.value}("");
                require(sent, "fee transfer failed");
                emit NoteArchived(noteId, commitment, msg.sender, msg.value);
            } else {
                // No vault configured — refund to prevent stuck ETH
                (bool sent,) = msg.sender.call{value: msg.value}("");
                require(sent, "refund failed");
            }
        }
    }

    function _advanceEpoch() internal {
        if (block.number >= epochStartBlock + BLOCKS_PER_EPOCH) {
            currentEpoch++;
            epochStartBlock = block.number;
        }
    }
}
