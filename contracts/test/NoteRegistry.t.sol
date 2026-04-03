// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {NoteRegistry} from "../src/NoteRegistry.sol";

contract NoteRegistryTest is Test {
    NoteRegistry public registry;
    address deployer = address(this);
    address sender = address(0x1);
    address recipient = address(0x2);
    address vault = address(0x3);
    address attacker = address(0x4);

    function setUp() public {
        registry = new NoteRegistry(vault);
        vm.deal(sender, 10 ether);
        vm.deal(recipient, 10 ether);
        vm.deal(attacker, 10 ether);
    }

    // --- Key registration ---

    function test_registerKeys() public {
        vm.prank(recipient);
        registry.registerKeys(new bytes(33), new bytes(1184));
        assertTrue(registry.registered(recipient));
    }

    function test_registerKeys_rejectsBadLength() public {
        vm.prank(recipient);
        vm.expectRevert("pkEc must be 33 bytes");
        registry.registerKeys(new bytes(32), new bytes(1184));
    }

    // --- Note posting ---

    function test_postFirstContact() public {
        bytes32 commitment = keccak256("c1");
        vm.prank(sender);
        registry.postFirstContact(commitment, new bytes(1769));
        assertEq(registry.nextNoteId(), 1);
        assertEq(registry.noteCommitments(0), commitment);
    }

    function test_postNote() public {
        vm.prank(sender);
        registry.postNote(keccak256("n1"), bytes16(uint128(42)), new bytes(632));
        assertEq(registry.nextNoteId(), 1);
    }

    function test_rejectZeroCommitment() public {
        vm.prank(sender);
        vm.expectRevert("zero commitment");
        registry.postFirstContact(bytes32(0), new bytes(100));
    }

    function test_noteIdIncrements() public {
        registry.postFirstContact(keccak256("a"), new bytes(100));
        registry.postNote(keccak256("b"), bytes16(uint128(1)), new bytes(632));
        assertEq(registry.nextNoteId(), 2);
    }

    function test_epochAdvances() public {
        registry.postFirstContact(keccak256("e1"), new bytes(100));
        assertEq(registry.currentEpoch(), 0);
        vm.roll(block.number + 7201);
        registry.postFirstContact(keccak256("e2"), new bytes(100));
        assertEq(registry.currentEpoch(), 1);
    }

    function test_multipleEpochsSkipped() public {
        registry.postFirstContact(keccak256("m1"), new bytes(100));
        assertEq(registry.currentEpoch(), 0);
        // Skip 3 full epochs with no posts
        vm.roll(block.number + 7200 * 3 + 1);
        registry.postFirstContact(keccak256("m2"), new bytes(100));
        assertEq(registry.currentEpoch(), 3);
    }

    // --- Minimum sender fee ---

    function test_minSenderFeeEnforced() public {
        registry.setMinSenderFee(0.001 ether);
        vm.prank(sender);
        vm.expectRevert("below min sender fee");
        registry.postFirstContact(keccak256("x"), new bytes(100));
    }

    function test_minSenderFeePasses() public {
        registry.setMinSenderFee(0.001 ether);
        vm.prank(sender);
        registry.postFirstContact{value: 0.001 ether}(keccak256("y"), new bytes(100));
        assertEq(registry.nextNoteId(), 1);
    }

    function test_zeroMinFeeAllowsFree() public {
        registry.postFirstContact(keccak256("free"), new bytes(100));
        assertEq(registry.nextNoteId(), 1);
    }

    // --- Fee forwarding ---

    function test_feeForwardedToVault() public {
        uint256 vaultBefore = vault.balance;
        vm.prank(sender);
        registry.postFirstContact{value: 0.001 ether}(keccak256("p"), new bytes(100));
        assertEq(vault.balance, vaultBefore + 0.001 ether);
        // Post-time fee does NOT mark as archived (that's archiveNote's job)
        assertFalse(registry.archived(0));
    }

    function test_feeRefundedWhenNoVault() public {
        NoteRegistry noVault = new NoteRegistry(address(0));
        uint256 senderBefore = sender.balance;
        vm.prank(sender);
        noVault.postFirstContact{value: 0.001 ether}(keccak256("rv"), new bytes(100));
        // ETH refunded
        assertEq(sender.balance, senderBefore);
        assertFalse(noVault.archived(0));
    }

    // --- Archival ---

    function test_archiveNote() public {
        registry.postNote(keccak256("ar"), bytes16(uint128(1)), new bytes(632));
        vm.prank(recipient);
        registry.archiveNote{value: 0.001 ether}(0);
        assertTrue(registry.archived(0));
    }

    function test_archiveNonexistentFails() public {
        vm.expectRevert("note does not exist");
        registry.archiveNote{value: 0.001 ether}(999);
    }

    function test_archiveRequiresFee() public {
        registry.postFirstContact(keccak256("af"), new bytes(100));
        vm.expectRevert("must send archival fee");
        registry.archiveNote(0);
    }

    function test_doubleArchiveFails() public {
        registry.postFirstContact(keccak256("da"), new bytes(100));
        registry.archiveNote{value: 0.001 ether}(0);
        vm.expectRevert("already archived");
        registry.archiveNote{value: 0.001 ether}(0);
    }

    // --- Subscription ---

    function test_depositAndWithdraw() public {
        vm.prank(recipient);
        registry.depositBalance{value: 1 ether}();
        assertEq(registry.balances(recipient), 1 ether);

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

    // --- spendNote: bound to noteId + one-time ---

    function test_spendNote() public {
        registry.postFirstContact(keccak256("sp"), new bytes(100));
        registry.setServerFeePerNote(0.001 ether);
        vm.prank(recipient);
        registry.depositBalance{value: 1 ether}();

        uint256 vaultBefore = vault.balance;
        vm.prank(recipient);
        registry.spendNote(0, keccak256("null-1"));

        assertTrue(registry.spent(0));
        assertTrue(registry.nullifiers(keccak256("null-1")));
        assertEq(vault.balance, vaultBefore + 0.001 ether);
    }

    function test_sameNoteCannotBeSpentTwice() public {
        registry.postFirstContact(keccak256("ds"), new bytes(100));
        registry.spendNote(0, keccak256("n1"));

        // Same noteId, different nullifier — fails because noteId is marked spent
        vm.expectRevert("note already spent");
        registry.spendNote(0, keccak256("n2"));
    }

    function test_sameNullifierCannotBeReused() public {
        registry.postFirstContact(keccak256("r1"), new bytes(100));
        registry.postFirstContact(keccak256("r2"), new bytes(100));

        bytes32 nullifier = keccak256("shared");
        registry.spendNote(0, nullifier);

        vm.expectRevert("nullifier already used");
        registry.spendNote(1, nullifier);
    }

    function test_spendNonexistentFails() public {
        vm.expectRevert("note does not exist");
        registry.spendNote(999, keccak256("bad"));
    }

    function test_spendInsufficientBalanceFails() public {
        registry.postFirstContact(keccak256("poor"), new bytes(100));
        registry.setServerFeePerNote(1 ether);
        vm.prank(recipient);
        vm.expectRevert("insufficient balance for fee");
        registry.spendNote(0, keccak256("null-poor"));
    }

    function test_spendWithZeroFee() public {
        registry.postFirstContact(keccak256("zf"), new bytes(100));
        registry.spendNote(0, keccak256("null-zf"));
        assertTrue(registry.spent(0));
    }

    // --- Admin: owner-only ---

    function test_onlyOwnerCanSetVault() public {
        vm.prank(attacker);
        vm.expectRevert("not owner");
        registry.setArchivalVault(attacker);

        registry.setArchivalVault(address(0x5));
        assertEq(registry.archivalVault(), address(0x5));
    }

    function test_onlyOwnerCanSetFees() public {
        vm.prank(attacker);
        vm.expectRevert("not owner");
        registry.setServerFeePerNote(1 ether);

        vm.prank(attacker);
        vm.expectRevert("not owner");
        registry.setMinSenderFee(1 ether);
    }

    function test_zeroVaultCannotBeHijacked() public {
        NoteRegistry noVault = new NoteRegistry(address(0));
        vm.prank(attacker);
        vm.expectRevert("not owner");
        noVault.setArchivalVault(attacker);
    }
}
