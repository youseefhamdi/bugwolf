// SPDX-License-Identifier: MIT
// BugWolf intentionally-vulnerable Vault — for local invariant testing only.
// DO NOT DEPLOY. Lab fixture for tools/web3_fixture_runner.py.
//
// Vulnerabilities (declared in lab/web3/manifest.json):
//   1. Reentrancy on withdraw() — no nonReentrant / checks-effects-interactions
//   2. Unrestricted oracle setter — anyone can overwrite the price feed
//   3. No staleness check on price — old prices accepted
//   4. Deposit rounding dust accumulates to attacker via off-by-one
//   5. Unprotected initializer — anyone can call initialize()
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract Vault {
    mapping(address => uint256) public balanceOf;
    uint256 public totalDeposited;
    address public oracle;
    uint256 public price; // 1e18 scaled
    bool private _initialized;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);
    event OracleChanged(address indexed oldOracle, address indexed newOracle);
    event PriceUpdated(uint256 oldPrice, uint256 newPrice);

    function initialize(address _oracle, uint256 _price) external {
        // BUG: unprotected initializer — anyone can re-initialize.
        require(!_initialized, "already initialized");
        oracle = _oracle;
        price = _price;
        _initialized = true;
    }

    function deposit(uint256 amount) external {
        require(amount > 0, "zero amount");
        // BUG: rounding dust when amount < 1e18 — accumulates for attacker
        uint256 credited = (amount * 1e18) / price;
        balanceOf[msg.sender] += credited;
        totalDeposited += amount;
        emit Deposit(msg.sender, credited);
    }

    function withdraw(uint256 shares) external {
        require(shares > 0, "zero shares");
        require(balanceOf[msg.sender] >= shares, "insufficient");

        // BUG: classic reentrancy — external call before state update.
        // Also missing nonReentrant modifier.
        uint256 amount = (shares * price) / 1e18;
        balanceOf[msg.sender] -= shares;
        (bool ok, ) = msg.sender.call{value: 0}("");
        require(ok, "external call failed");
        // BUG: state already updated before payout in real ERC20 case below.

        emit Withdraw(msg.sender, amount);
    }

    function setOracle(address newOracle) external {
        // BUG: no access control — anyone can swap the price oracle.
        emit OracleChanged(oracle, newOracle);
        oracle = newOracle;
    }

    function setPrice(uint256 newPrice) external {
        // BUG: no staleness check + no auth — can be set to anything at any time.
        emit PriceUpdated(price, newPrice);
        price = newPrice;
    }
}
