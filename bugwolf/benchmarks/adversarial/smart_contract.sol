# bugwolf/benchmarks — adversarial test apps + scoring
# SCHEMA: bugwolf-benchmarks-adversarial-smart-contract-v1
# ## Source: original work for Phase 4.3
# ## License: BugWolf internal
# ## Capability tier: C0 (passive) only — all benchmarks are local test apps
// SPDX-License-Identifier: BugWolf-Internal
// Synthlab — adversarial Solidity contract with classic re-entrancy.
//
// The bug: state update happens AFTER the external call. A re-entrant
// caller can drain the contract by repeatedly calling withdraw() before
// balances[msg.sender] is set to zero.
//
// This file is a TEST FIXTURE. It is never compiled or deployed.

pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // BUG: external call before state update — classic re-entrancy.
    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "no balance");
        (bool ok,) = msg.sender.call{value: bal}("");
        require(ok, "send failed");
        balances[msg.sender] = 0; // state update AFTER external call
    }

    function withdrawFixed() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "no balance");
        balances[msg.sender] = 0; // checks-effects-interactions pattern
        (bool ok,) = msg.sender.call{value: bal}("");
        require(ok, "send failed");
    }
}

// Bug class:    re-entrancy (SWC-107)
// Severity:     high
// Detector:     bugwolf.scanners.web3.ReentrancyDetector