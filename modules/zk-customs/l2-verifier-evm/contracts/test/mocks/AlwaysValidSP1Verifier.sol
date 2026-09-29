// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "../../src/interfaces/ISP1Verifier.sol";

/// @notice Test-only stand-in for a real SP1 verifier — accepts any proof unconditionally.
/// Used for Settlement.sol's own logic tests (replay protection, event shape), which are
/// independent of proof validity. Real SP1-proof rejection is NOT exercised by these tests —
/// see the plan's Stage 5 for the optional follow-up using Succinct's real SP1MockVerifier.
contract AlwaysValidSP1Verifier is ISP1Verifier {
    function verifyProof(bytes32, bytes calldata, bytes calldata) external pure override {
        // never reverts
    }
}
