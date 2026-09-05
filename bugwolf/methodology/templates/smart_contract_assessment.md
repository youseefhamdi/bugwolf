# Smart Contract Assessment

> Solidity / EVM smart contract security review runbook.

_Template file: `smart_contract_assessment.md`_

## Scoping

- Receive source code, deployment addresses, compiler version, optimizer settings.
- Identify dependencies: OpenZeppelin, Uniswap, AAVE, custom libraries.
- Identify the upgrade pattern: transparent, UUPS, diamond, beacon.
- Identify the governance and admin keys, multisigs, timelocks.
- Identify the in-scope contracts and out-of-scope libraries.

## Static Analysis

- Run Slither with all detectors enabled.
- Run Mythril for symbolic execution on critical functions.
- Run Echidna for property-based fuzzing (custom invariants).
- Manual review: reentrancy, access control, arithmetic, signature replay.
- Compare code against SWC registry and known exploit patterns.

## Access Control

- Verify every state-changing function has an access modifier.
- Verify initializable contracts cannot be re-initialized.
- Verify admin keys are behind a multisig + timelock.
- Verify role assignments: DEFAULT_ADMIN_ROLE, custom roles, role hierarchy.
- Verify emergency pause/unpause is bounded and audited.

## Reentrancy

- Check external calls: token transfers, hooks, oracles, cross-chain bridges.
- Verify checks-effects-interactions ordering.
- Verify reentrancy guards on every state-changing external call site.
- Verify read-only reentrancy: view functions returning stale state mid-callback.
- Verify cross-function reentrancy across the contract surface.

## Token Logic

- Verify ERC-20 compliance: return values, fee-on-transfer, rebasing tokens.
- Verify oracle freshness and staleness checks.
- Verify slippage protection on swaps.
- Verify flashloan guards and reentrancy protections on lending.
- Verify share-price inflation attacks on vault deposits.

## Reporting

- Findings mapped to SWC registry and Trail of Bits classification.
- Severity via CVSS 3.1 + impact in USD (TVL-at-risk, governance).
- Recommendations include a fix PR or patch contract.
- Public disclosure coordinated with the project team.

## Outputs

- `findings/*.yaml` — registered findings with severity and reproducer.
- `state/engagement/<id>/` — daily notes, surface map, evidence.
- `report/final.md` — final report delivered to the customer.
- `report/citations.md` — auto-generated methodology citations.

## Acceptance Criteria

- All findings reproducible from the documented evidence.
- Severity calibrated to the customer's business context.
- Every finding has at least one fix recommendation.
- Methodology citations attached via CitationEngine.
- Daily standups held; deviations from the runbook documented.
