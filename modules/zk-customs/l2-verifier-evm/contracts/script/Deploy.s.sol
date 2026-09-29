// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {Settlement} from "../src/Settlement.sol";

/// Deploys Settlement against an already-deployed ISP1Verifier on whichever EVM chain
/// L2_RPC_URL points at. Usage (see the workspace's package.json "deploy:contract" script):
///   forge script script/Deploy.s.sol --rpc-url $L2_RPC_URL --broadcast --private-key $KEY \
///     --sig "run(address,bytes32)" $SP1_VERIFIER_ADDRESS $SP1_PROGRAM_VKEY
contract Deploy is Script {
    function run(address verifierAddress, bytes32 programVKey) external returns (Settlement) {
        vm.startBroadcast();
        Settlement settlement = new Settlement(verifierAddress, programVKey);
        vm.stopBroadcast();

        console.log("Settlement deployed at:", address(settlement));
        return settlement;
    }
}
