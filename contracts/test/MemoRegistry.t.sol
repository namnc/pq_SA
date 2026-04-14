// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MemoRegistry} from "../src/MemoRegistry.sol";

contract MemoRegistryTest is Test {
    MemoRegistry public registry;
    address sender = address(0x1);
    address recipient = address(0x2);

    event FirstContact(uint64 indexed memoId, uint256 indexed epoch, bytes payload);
    event Memo(uint64 indexed memoId, uint256 indexed epoch, bytes16 nonce, uint8 viewTag, bytes8 confirmTag);
    event KeyRegistered(address indexed recipient, bytes spendingPk, bytes viewingPkEc, bytes viewingEk);

    function setUp() public {
        registry = new MemoRegistry();
    }

    function test_registerKeys() public {
        bytes memory spendingPk = new bytes(33);
        spendingPk[0] = 0x02;
        bytes memory viewingPkEc = new bytes(33);
        viewingPkEc[0] = 0x03;
        vm.prank(recipient);
        registry.registerKeys(spendingPk, viewingPkEc, new bytes(1184));
        // Registration is event-only (no on-chain state) — verify via nextMemoId remaining 0
        assertEq(registry.nextMemoId(), 0);
    }

    function test_registerKeysRejectsBadSpendingPk() public {
        vm.prank(recipient);
        vm.expectRevert("spendingPk must be 33 bytes");
        registry.registerKeys(new bytes(32), new bytes(33), new bytes(1184));
    }

    function test_registerKeysRejectsBadViewingPkEc() public {
        vm.prank(recipient);
        vm.expectRevert("viewingPkEc must be 33 bytes");
        registry.registerKeys(new bytes(33), new bytes(32), new bytes(1184));
    }

    function test_registerKeysRejectsBadViewingEk() public {
        vm.prank(recipient);
        vm.expectRevert("viewingEk must be 1184 bytes");
        registry.registerKeys(new bytes(33), new bytes(33), new bytes(100));
    }

    function test_postFirstContact() public {
        vm.prank(sender);
        registry.postFirstContact(new bytes(1121));
        assertEq(registry.nextMemoId(), 1);
    }

    function test_postFirstContactRejectsBadLength() public {
        vm.prank(sender);
        vm.expectRevert("payload must be 1121 bytes (33 EPK + 1088 KEM ct)");
        registry.postFirstContact(new bytes(100));
    }

    function test_postMemo() public {
        vm.prank(sender);
        registry.postMemo(bytes16(uint128(42)), 0xAB, bytes8(0xDEADBEEFCAFEBABE));
        assertEq(registry.nextMemoId(), 1);
    }

    function test_memoIdIncrements() public {
        registry.postFirstContact(new bytes(1121));
        registry.postMemo(bytes16(uint128(1)), 0x01, bytes8(0x1111111111111111));
        registry.postMemo(bytes16(uint128(2)), 0x02, bytes8(0x2222222222222222));
        assertEq(registry.nextMemoId(), 3);
    }

    function test_epochAdvances() public {
        registry.postFirstContact(new bytes(1121));
        assertEq(registry.currentEpoch(), 0);
        vm.roll(block.number + 7201);
        registry.postMemo(bytes16(uint128(1)), 0x01, bytes8(0x1111111111111111));
        assertEq(registry.currentEpoch(), 1);
    }

    function test_multipleEpochAdvance() public {
        vm.roll(block.number + 14401);
        registry.postMemo(bytes16(uint128(1)), 0x01, bytes8(0x1111111111111111));
        assertEq(registry.currentEpoch(), 2);
    }

    function test_emitsFirstContactEvent() public {
        bytes memory payload = new bytes(1121);
        vm.expectEmit(true, true, false, true);
        emit FirstContact(0, 0, payload);
        registry.postFirstContact(payload);
    }

    function test_emitsMemoEvent() public {
        vm.expectEmit(true, true, false, true);
        emit Memo(0, 0, bytes16(uint128(42)), 0xAB, bytes8(0xDEADBEEFCAFEBABE));
        registry.postMemo(bytes16(uint128(42)), 0xAB, bytes8(0xDEADBEEFCAFEBABE));
    }

    function test_registerKeysRejectsSameSpendingAndViewing() public {
        bytes memory sameKey = new bytes(33);
        sameKey[0] = 0x02; // nonzero to make it look like a real key
        vm.prank(recipient);
        vm.expectRevert("spending and viewing EC keys must differ");
        registry.registerKeys(sameKey, sameKey, new bytes(1184));
    }

    function test_gasFirstContact() public {
        uint256 g = gasleft();
        registry.postFirstContact(new bytes(1121));
        emit log_named_uint("postFirstContact gas", g - gasleft());
    }

    function test_gasMemo() public {
        uint256 g = gasleft();
        registry.postMemo(bytes16(uint128(42)), 0xAB, bytes8(0xDEADBEEFCAFEBABE));
        emit log_named_uint("postMemo gas", g - gasleft());
    }
}
