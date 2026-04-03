// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {NoteRegistry} from "../src/NoteRegistry.sol";

contract NoteRegistryTest is Test {
    NoteRegistry public registry;
    address sender = address(0x1);
    address recipient = address(0x2);
    address vault = address(0x3);

    event FirstContact(uint64 indexed noteId, uint256 indexed epoch, bytes32 commitment, bytes payload);
    event NotePosted(uint64 indexed noteId, uint256 indexed epoch, bytes32 commitment, bytes16 nonce, bytes ciphertext);
    event KeyRegistered(address indexed recipient, bytes pkEc, bytes ekKem);
    event NoteArchived(uint64 indexed noteId, bytes32 commitment, address payer, uint256 fee);
    event BalanceDeposited(address indexed recipient, uint256 amount);
    event BalanceWithdrawn(address indexed recipient, uint256 amount);
    event NoteSpent(uint64 indexed noteId, bytes32 nullifier, uint256 feePaid);

    function setUp() public {
        registry = new NoteRegistry(vault);
        vm.deal(sender, 10 ether);
        vm.deal(recipient, 10 ether);
    }

    // --- Core note posting ---

    function test_registerKeys() public {
        bytes memory pkEc = new bytes(33);
        bytes memory ekKem = new bytes(1184);

        vm.prank(recipient);
        vm.expectEmit(true, false, false, true);
        emit KeyRegistered(recipient, pkEc, ekKem);
        registry.registerKeys(pkEc, ekKem);
        assertTrue(registry.registered(recipient));
    }

    function test_registerKeys_rejectsBadLength() public {
        vm.prank(recipient);
        vm.expectRevert("pkEc must be 33 bytes");
        registry.registerKeys(new bytes(32), new bytes(1184));
    }

    function test_postFirstContact() public {
        bytes32 commitment = keccak256("test commitment");
        bytes memory payload = new bytes(1769);

        vm.prank(sender);
        registry.postFirstContact(commitment, payload);
        assertEq(registry.nextNoteId(), 1);
        assertEq(registry.noteCommitments(0), commitment);
    }

    function test_postNote() public {
        bytes32 commitment = keccak256("test note");
        vm.prank(sender);
        registry.postNote(commitment, bytes16(uint128(42)), new bytes(632));
        assertEq(registry.nextNoteId(), 1);
    }

    function test_noteIdIncrementsAcrossBothTypes() public {
        registry.postFirstContact(keccak256("c1"), new bytes(100));
        registry.postNote(keccak256("c2"), bytes16(uint128(1)), new bytes(632));
        assertEq(registry.nextNoteId(), 2);
    }

    function test_epochAdvances() public {
        registry.postFirstContact(keccak256("c"), new bytes(100));
        assertEq(registry.currentEpoch(), 0);
        vm.roll(block.number + 7201);
        registry.postFirstContact(keccak256("c"), new bytes(100));
        assertEq(registry.currentEpoch(), 1);
    }

    // --- Sender-pays archival ---

    function test_senderPaysArchival() public {
        bytes32 commitment = keccak256("archived");
        uint256 fee = 0.001 ether;
        uint256 vaultBefore = vault.balance;

        vm.prank(sender);
        registry.postFirstContact{value: fee}(commitment, new bytes(100));

        assertEq(vault.balance, vaultBefore + fee);
        assertTrue(registry.archived(0));
    }

    function test_receiverPaysArchival() public {
        bytes32 commitment = keccak256("receiver pays");
        vm.prank(sender);
        registry.postNote(commitment, bytes16(uint128(1)), new bytes(632));

        uint256 fee = 0.001 ether;
        vm.prank(recipient);
        registry.archiveNote{value: fee}(0);
        assertTrue(registry.archived(0));
    }

    function test_archiveNonexistentNoteFails() public {
        vm.prank(recipient);
        vm.expectRevert("note does not exist");
        registry.archiveNote{value: 0.001 ether}(999);
    }

    function test_archiveRequiresFee() public {
        registry.postFirstContact(keccak256("x"), new bytes(100));
        vm.prank(recipient);
        vm.expectRevert("must send archival fee");
        registry.archiveNote(0);
    }

    function test_noFeeNoArchival() public {
        registry.postFirstContact(keccak256("no fee"), new bytes(100));
        assertFalse(registry.archived(0));
    }

    function test_noVaultNoArchival() public {
        NoteRegistry noVault = new NoteRegistry(address(0));
        noVault.postFirstContact(keccak256("no vault"), new bytes(100));
        assertFalse(noVault.archived(0));
    }

    // --- Subscription: deposit/withdraw ---

    function test_depositBalance() public {
        vm.prank(recipient);
        vm.expectEmit(true, false, false, true);
        emit BalanceDeposited(recipient, 1 ether);
        registry.depositBalance{value: 1 ether}();

        assertEq(registry.balances(recipient), 1 ether);
    }

    function test_withdrawBalance() public {
        vm.prank(recipient);
        registry.depositBalance{value: 1 ether}();

        uint256 before = recipient.balance;
        vm.prank(recipient);
        registry.withdrawBalance(0.5 ether);

        assertEq(registry.balances(recipient), 0.5 ether);
        assertEq(recipient.balance, before + 0.5 ether);
    }

    function test_withdrawInsufficientFails() public {
        vm.prank(recipient);
        registry.depositBalance{value: 0.1 ether}();

        vm.prank(recipient);
        vm.expectRevert("insufficient balance");
        registry.withdrawBalance(1 ether);
    }

    // --- Pay-on-spend ---

    function test_spendNote() public {
        // Setup: post note, set fee, deposit balance
        bytes32 commitment = keccak256("spendable");
        registry.postFirstContact(commitment, new bytes(100));

        uint256 fee = 0.001 ether;
        vm.prank(vault);
        registry.setServerFeePerNote(fee);

        vm.prank(recipient);
        registry.depositBalance{value: 1 ether}();

        // Spend
        bytes32 nullifier = keccak256("nullifier-1");
        uint256 vaultBefore = vault.balance;

        vm.prank(recipient);
        vm.expectEmit(true, false, false, true);
        emit NoteSpent(0, nullifier, fee);
        registry.spendNote(0, nullifier);

        assertEq(vault.balance, vaultBefore + fee);
        assertEq(registry.balances(recipient), 1 ether - fee);
        assertTrue(registry.nullifiers(nullifier));
    }

    function test_doubleSpendFails() public {
        registry.postFirstContact(keccak256("ds"), new bytes(100));
        bytes32 nullifier = keccak256("null-ds");

        vm.prank(recipient);
        registry.spendNote(0, nullifier);

        vm.prank(recipient);
        vm.expectRevert("already spent");
        registry.spendNote(0, nullifier);
    }

    function test_spendInsufficientBalanceFails() public {
        registry.postFirstContact(keccak256("poor"), new bytes(100));

        vm.prank(vault);
        registry.setServerFeePerNote(1 ether);

        vm.prank(recipient);
        vm.expectRevert("insufficient balance for fee");
        registry.spendNote(0, keccak256("null-poor"));
    }

    function test_spendWithZeroFee() public {
        registry.postFirstContact(keccak256("free"), new bytes(100));
        // serverFeePerNote defaults to 0

        vm.prank(recipient);
        registry.spendNote(0, keccak256("null-free"));
        // Should succeed without any balance needed
    }

    function test_spendNonexistentNoteFails() public {
        vm.prank(recipient);
        vm.expectRevert("note does not exist");
        registry.spendNote(999, keccak256("null-bad"));
    }
}
