// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Hand-vendored from Succinct's `sp1-contracts` (ISP1Verifier.sol) rather than pulled in
/// via `forge install` (which defaults to git submodules — none exist elsewhere in this repo).
/// Re-check this signature against the current `sp1-contracts` repo before deploying against a
/// real verifier: exact visibility/revert-vs-return-bool behavior should be confirmed, not assumed.
interface ISP1Verifier {
    /// @notice Verifies a proof with given public values and vkey.
    /// @dev Reverts if the proof is invalid.
    /// @param programVKey The verification key for the RISC-V program.
    /// @param publicValues The public values encoded as bytes.
    /// @param proofBytes The proof of the program's execution the SP1 zkVM encoded as bytes.
    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external view;
}
