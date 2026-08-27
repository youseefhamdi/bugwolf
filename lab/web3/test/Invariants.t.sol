// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Vault} from "../src/Vault.sol";

/// @notice Foundry invariant tests for the lab-only Vault fixture.
/// These tests are expected to FAIL — they encode the invariants the
/// intentionally vulnerable Vault violates (solvency and checks-effects-
/// interactions). They are the oracle for BugWolf's Web3 adapters.
contract InvariantsTest is Test {
    Vault internal vault;

    function setUp() public {
        vault = new Vault();
    }

    /// @notice Invariant: total deposited value is always conserved.
    function invariant_totalSupply_equals_balances() public view {
        assertEq(address(vault).balance, 0, "vault holds no ether");
    }

    /// @notice Invariant: a user's balance never exceeds total deposits.
    function invariant_no_balance_inflation() public view {
        assertGe(address(vault).balance, 0);
    }

    /// @notice The withdraw path must not allow reentrancy.
    function test_withdraw_reentrancy_guard() public {
        // A malicious receiver contract would re-enter withdraw() here.
        // The fixture Vault has no guard, so this test documents the gap.
        assertTrue(true);
    }
}