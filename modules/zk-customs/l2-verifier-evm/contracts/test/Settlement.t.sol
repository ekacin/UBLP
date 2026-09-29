// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Settlement} from "../src/Settlement.sol";
import {AlwaysValidSP1Verifier} from "./mocks/AlwaysValidSP1Verifier.sol";

contract SettlementTest is Test {
    Settlement settlement;
    AlwaysValidSP1Verifier verifier;

    bytes32 constant PROGRAM_VKEY = bytes32(uint256(0xBEEF));

    function setUp() public {
        verifier = new AlwaysValidSP1Verifier();
        settlement = new Settlement(address(verifier), PROGRAM_VKEY);
    }

    function _settleOnce(bytes32 documentIdHash) internal {
        settlement.settle(
            keccak256("documentHash"),
            keccak256("ministryPubKeyHash"),
            documentIdHash,
            keccak256("holderPubKeyHash"),
            "did:ublp:agent:default",
            hex"1234"
        );
    }

    function test_SettleStoresRecordAndMarksSettled() public {
        bytes32 documentIdHash = keccak256("doc-1");
        _settleOnce(documentIdHash);

        assertTrue(settlement.isSettled(documentIdHash));

        (bytes32 documentHash, bytes32 ministryPubKeyHash, bytes32 holderPubKeyHash, address settler, uint64 settledAt)
        = settlement.records(documentIdHash);
        assertEq(documentHash, keccak256("documentHash"));
        assertEq(ministryPubKeyHash, keccak256("ministryPubKeyHash"));
        assertEq(holderPubKeyHash, keccak256("holderPubKeyHash"));
        assertEq(settler, address(this));
        assertEq(settledAt, block.timestamp);
    }

    function test_SettleEmitsSettledEvent() public {
        bytes32 documentIdHash = keccak256("doc-2");

        vm.expectEmit(true, true, false, true);
        emit Settlement.Settled(
            documentIdHash,
            keccak256("documentHash"),
            keccak256("ministryPubKeyHash"),
            "did:ublp:agent:default",
            address(this),
            block.timestamp
        );
        _settleOnce(documentIdHash);
    }

    function test_RevertsOnDuplicateDocumentIdHash() public {
        bytes32 documentIdHash = keccak256("doc-3");
        _settleOnce(documentIdHash);

        vm.expectRevert(abi.encodeWithSelector(Settlement.AlreadySettled.selector, documentIdHash));
        _settleOnce(documentIdHash);
    }

    function test_IsSettledFalseForUnknownDocument() public view {
        assertFalse(settlement.isSettled(keccak256("never-settled")));
    }

    function test_DistinctDocumentIdHashesDoNotCollide() public {
        _settleOnce(keccak256("doc-a"));
        _settleOnce(keccak256("doc-b"));

        assertTrue(settlement.isSettled(keccak256("doc-a")));
        assertTrue(settlement.isSettled(keccak256("doc-b")));
    }
}
