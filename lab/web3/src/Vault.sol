// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Lab-only vulnerable vault for BugWolf Web3 fixture testing.
/// Intentionally contains: reentrancy (no checks-effects-interactions),
/// missing use of nonReentrant, and a settable oracle without staleness checks.
/// This contract must never be deployed on a real network.
contract Vault {
    mapping(address => uint256) public balances;
    address public owner;
    address public priceFeed;

    event Withdrawn(address indexed user, uint256 amount);
    event Deposited(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    function setOracle(address _oracle) external {
        // VULN: any caller can set the oracle (missing owner check).
        priceFeed = _oracle;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        // VULN: state update happens AFTER the external call (reentrancy).
        require(balances[msg.sender] >= amount, "insufficient balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
        emit Withdrawn(msg.sender, amount);
    }

    function collateralized(address user) public view returns (bool) {
        // VULN: price read has no staleness check.
        return balances[user] >= oraclePrice();
    }

    function oraclePrice() public view returns (uint256) {
        return priceFeed == address(0) ? 1 ether : uint256(uint160(priceFeed)) % 1000;
    }
}