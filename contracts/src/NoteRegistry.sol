// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title NoteRegistry — Append-only log for PQ in-band secret distribution
/// @notice Stores first-contact KEM ciphertexts and encrypted notes as events.
///         All verification and decryption happens off-chain on the recipient side.
///         Supports three payment models for archival and OMR server incentives:
///         1. Sender-pays: include msg.value when posting (forwarded to archival vault)
///         2. Receiver subscription: deposit balance, auto-deducted on note spend
///         3. Pay-on-spend: server archives speculatively, gets paid when note is spent
contract NoteRegistry {
    uint64 public nextNoteId;
    uint256 public currentEpoch;
    uint256 public epochStartBlock;
    uint256 public constant BLOCKS_PER_EPOCH = 7200; // ~1 day on mainnet

    /// @notice Address that receives archival/OMR fees.
    address public archivalVault;

    /// @notice Fee deducted from recipient balance per note spend.
    uint256 public serverFeePerNote;

    /// @notice Recipient subscription balances for pay-on-spend model.
    mapping(address => uint256) public balances;

    /// @notice Mapping from noteId to commitment.
    mapping(uint64 => bytes32) public noteCommitments;

    /// @notice Tracks whether a note has been archived.
    mapping(uint64 => bool) public archived;

    /// @notice Tracks whether a note has been spent (nullified).
    mapping(bytes32 => bool) public nullifiers;

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

    event BalanceDeposited(address indexed recipient, uint256 amount);
    event BalanceWithdrawn(address indexed recipient, uint256 amount);
    event NoteSpent(uint64 indexed noteId, bytes32 nullifier, uint256 feePaid);

    mapping(address => bool) public registered;

    constructor(address _archivalVault) {
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
    //  Note posting (sender-pays archival is optional via msg.value)
    // =========================================================================

    function postFirstContact(bytes32 commitment, bytes calldata payload) external payable {
        _advanceEpoch();
        uint64 noteId = nextNoteId++;
        noteCommitments[noteId] = commitment;
        emit FirstContact(noteId, currentEpoch, commitment, payload);
        _handleArchivalFee(noteId, commitment);
    }

    function postNote(
        bytes32 commitment,
        bytes16 nonce,
        bytes calldata ciphertext
    ) external payable {
        _advanceEpoch();
        uint64 noteId = nextNoteId++;
        noteCommitments[noteId] = commitment;
        emit NotePosted(noteId, currentEpoch, commitment, nonce, ciphertext);
        _handleArchivalFee(noteId, commitment);
    }

    // =========================================================================
    //  Receiver-pays archival (within blob window)
    // =========================================================================

    function archiveNote(uint64 noteId) external payable {
        require(noteCommitments[noteId] != bytes32(0), "note does not exist");
        require(msg.value > 0, "must send archival fee");
        _handleArchivalFee(noteId, noteCommitments[noteId]);
    }

    // =========================================================================
    //  Subscription: deposit/withdraw balance for pay-on-spend
    // =========================================================================

    /// @notice Deposit ETH as subscription balance. Covers archival + OMR fees
    ///         that are deducted when spending notes.
    function depositBalance() external payable {
        require(msg.value > 0, "must send value");
        balances[msg.sender] += msg.value;
        emit BalanceDeposited(msg.sender, msg.value);
    }

    /// @notice Withdraw unused subscription balance.
    function withdrawBalance(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;
        (bool sent,) = msg.sender.call{value: amount}("");
        require(sent, "withdraw failed");
        emit BalanceWithdrawn(msg.sender, amount);
    }

    // =========================================================================
    //  Pay-on-spend: recipient pays server when spending (nullifying) a note
    // =========================================================================

    /// @notice Spend (nullify) a note. Deducts serverFeePerNote from the caller's
    ///         balance and forwards it to the archival vault / OMR server.
    ///         The server is incentivized to store and serve note data because it
    ///         only gets paid when notes are actually spent.
    /// @param noteId The note being spent
    /// @param nullifier The nullifier (prevents double-spend)
    function spendNote(uint64 noteId, bytes32 nullifier) external {
        require(noteCommitments[noteId] != bytes32(0), "note does not exist");
        require(!nullifiers[nullifier], "already spent");
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
    //  Admin
    // =========================================================================

    function setArchivalVault(address _archivalVault) external {
        require(
            archivalVault == address(0) || msg.sender == archivalVault,
            "not authorized"
        );
        archivalVault = _archivalVault;
    }

    function setServerFeePerNote(uint256 _fee) external {
        require(msg.sender == archivalVault, "not authorized");
        serverFeePerNote = _fee;
    }

    // =========================================================================
    //  Internal
    // =========================================================================

    function _handleArchivalFee(uint64 noteId, bytes32 commitment) internal {
        if (msg.value > 0 && archivalVault != address(0)) {
            archived[noteId] = true;
            (bool sent,) = archivalVault.call{value: msg.value}("");
            require(sent, "archival fee transfer failed");
            emit NoteArchived(noteId, commitment, msg.sender, msg.value);
        }
    }

    function _advanceEpoch() internal {
        if (block.number >= epochStartBlock + BLOCKS_PER_EPOCH) {
            currentEpoch++;
            epochStartBlock = block.number;
        }
    }
}
