// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MemoRegistry} from "../src/MemoRegistry.sol";

contract MemoRegistryTest is Test {
    MemoRegistry public registry;
    address sender = address(0x1);
    address recipient = address(0x2);

    event FirstContact(uint64 indexed memoId, uint256 indexed epoch, bytes payload);
    event Memo(uint64 indexed memoId, uint256 indexed epoch, bytes16 nonce, bytes pvwClue);
    event KeyRegistered(address indexed recipient, bytes pkEc, bytes ekKem);

    function setUp() public {
        registry = new MemoRegistry();
        vm.deal(sender, 10 ether);
    }

    function test_registerKeys() public {
        vm.prank(recipient);
        registry.registerKeys(new bytes(33), new bytes(1184));
        assertTrue(registry.registered(recipient));
    }

    function test_postFirstContact() public {
        vm.prank(sender);
        registry.postFirstContact(new bytes(1769));
        assertEq(registry.nextMemoId(), 1);
    }

    function test_postMemo() public {
        vm.prank(sender);
        registry.postMemo(bytes16(uint128(42)), new bytes(0));
        assertEq(registry.nextMemoId(), 1);
    }

    function test_postMemoWithPvwClue() public {
        vm.prank(sender);
        registry.postMemo(bytes16(uint128(42)), new bytes(52));
        assertEq(registry.nextMemoId(), 1);
    }

    function test_postMemoRejectsBadClueLength() public {
        vm.prank(sender);
        vm.expectRevert("pvwClue must be 52 bytes if provided");
        registry.postMemo(bytes16(uint128(1)), new bytes(30));
    }

    function test_memoIdIncrements() public {
        registry.postFirstContact(new bytes(100));
        registry.postMemo(bytes16(uint128(1)), new bytes(0));
        registry.postMemo(bytes16(uint128(2)), new bytes(52));
        assertEq(registry.nextMemoId(), 3);
    }

    function test_epochAdvances() public {
        registry.postFirstContact(new bytes(100));
        assertEq(registry.currentEpoch(), 0);
        vm.roll(block.number + 7201);
        registry.postMemo(bytes16(uint128(1)), new bytes(0));
        assertEq(registry.currentEpoch(), 1);
    }

    function test_minFeeEnforced() public {
        registry.setMinPostFee(0.001 ether);
        vm.prank(sender);
        vm.expectRevert("below min fee");
        registry.postMemo(bytes16(uint128(1)), new bytes(0));
    }

    function test_minFeePasses() public {
        registry.setMinPostFee(0.001 ether);
        vm.prank(sender);
        registry.postMemo{value: 0.001 ether}(bytes16(uint128(1)), new bytes(0));
        assertEq(registry.nextMemoId(), 1);
    }

    function test_gasMemoWithoutClue() public {
        vm.prank(sender);
        uint256 g = gasleft();
        registry.postMemo(bytes16(uint128(42)), new bytes(0));
        emit log_named_uint("postMemo (no clue) gas", g - gasleft());
    }

    function test_gasMemoWithClue() public {
        vm.prank(sender);
        uint256 g = gasleft();
        registry.postMemo(bytes16(uint128(42)), new bytes(52));
        emit log_named_uint("postMemo (52B clue) gas", g - gasleft());
    }
}
