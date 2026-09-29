// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.20;

import {ISP1Verifier} from "./interfaces/ISP1Verifier.sol";

/// @notice Real, on-chain settlement for UBLP's ZK Customs Clearance module — replaces
/// `l2-verifier-mock`'s off-chain, file-backed "trust a JSON response" model with a
/// cryptographic, on-chain SP1 Groth16/PLONK proof check. Chain-agnostic by design: this
/// contract is deployed by whoever runs the module, on whichever EVM chain they choose, and
/// pointed at whichever `ISP1Verifier` deployment exists there.
///
/// `settle()` is deliberately permissionless — the ZK proof itself is the authorization, the
/// same trust model Succinct's own on-chain examples use. Replay protection mirrors
/// `l2-verifier-mock`'s own `documentIdHash`-uniqueness check, as real contract storage instead
/// of a JSON file. `holderDid` is event-only (never written to storage) since it isn't needed
/// for the replay gate and string storage is unnecessarily expensive.
contract Settlement {
    ISP1Verifier public immutable verifier;
    bytes32 public immutable programVKey;

    struct Record {
        bytes32 documentHash;
        bytes32 ministryPubKeyHash; // SHA256(ministryPubKeyRaw) — the circuit's public output[1]
        bytes32 holderPubKeyHash;
        address settler;
        uint64 settledAt;
    }

    /// @dev Keyed by documentIdHash — the replay-protection gate.
    mapping(bytes32 => Record) public records;

    error AlreadySettled(bytes32 documentIdHash);

    event Settled(
        bytes32 indexed documentIdHash,
        bytes32 documentHash,
        bytes32 ministryPubKeyHash,
        string holderDid,
        address indexed settler,
        uint256 settledAt
    );

    constructor(address verifierAddress, bytes32 _programVKey) {
        verifier = ISP1Verifier(verifierAddress);
        programVKey = _programVKey;
    }

    function settle(
        bytes32 documentHash,
        bytes32 ministryPubKeyHash,
        bytes32 documentIdHash,
        bytes32 holderPubKeyHash,
        string calldata holderDid,
        bytes calldata proofBytes
    ) external {
        if (records[documentIdHash].settledAt != 0) revert AlreadySettled(documentIdHash);

        // Matches the SP1 circuit's four sequential io::commit(&[u8;32]) calls, in order —
        // bincode serializes fixed-size arrays with no length prefix, so the committed public
        // values are a flat 128-byte concatenation identical to this ABI encoding (verified
        // against the sp1-lib 4.2.1 source, see plan Stage 0).
        bytes memory publicValues = abi.encode(documentHash, ministryPubKeyHash, documentIdHash, holderPubKeyHash);
        verifier.verifyProof(programVKey, publicValues, proofBytes); // reverts on invalid proof

        // casting to 'uint64' is safe: block.timestamp won't exceed uint64's range until year 584942
        // forge-lint: disable-next-line(unsafe-typecast)
        Record memory record = Record(documentHash, ministryPubKeyHash, holderPubKeyHash, msg.sender, uint64(block.timestamp));
        records[documentIdHash] = record;

        emit Settled(documentIdHash, documentHash, ministryPubKeyHash, holderDid, msg.sender, block.timestamp);
    }

    function isSettled(bytes32 documentIdHash) external view returns (bool) {
        return records[documentIdHash].settledAt != 0;
    }
}
