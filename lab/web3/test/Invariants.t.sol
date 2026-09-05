// SPDX-License-Identifier: MIT
// BugWolf Foundry-style invariant tests for the vulnerable Vault.
// Intentionally exposes invariants that the buggy Vault violates.
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/Vault.sol";

contract VaultInvariants is Test {
    Vault vault;
    address attacker = address(0xBADBEEF);
    address honest = address(0xCAFE);

    function setUp() public {
        vault = new Vault();
        vault.initialize(address(this), 1e18); // 1:1 price
    }

    /// @notice Sum of depositor balances must equal vault accounting.
    function invariant_sumOfBalances() public view {
        uint256 sum = vault.balanceOf(attacker) + vault.balanceOf(honest);
        // Withdraw rounds DOWN; deposits round DOWN — totalDeposited can drift.
        // Invariant: sum <= totalDeposited (modulo rounding).
        assertLe(sum, vault.totalDeposited());
    }

    /// @notice Oracle address is never address(0) after init.
    function invariant_oracleNonZero() public view {
        assertTrue(vault.oracle() != address(0), "oracle zeroed");
    }

    /// @notice Price is never zero (would lock all withdrawals to 0).
    function invariant_priceNonZero() public view {
        assertGt(vault.price(), 0, "price zeroed");
    }

    /// @notice Foundry fuzz: deposits must never exceed credited balance.
    function testFuzz_depositCreditsCorrectly(uint256 amount) public {
        amount = bound(amount, 1, 1e30);
        uint256 before = vault.balanceOf(honest);
        vault.deposit(amount);
        uint256 after_ = vault.balanceOf(honest);
        // credited = amount * 1e18 / price (rounds down)
        assertGe(after_ - before, amount / vault.price());
    }
}
