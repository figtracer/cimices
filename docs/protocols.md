# Protocol audit knowledge

`data/protocols.json` separates reusable failure modes from historical findings.
Twenty-six findings from Code4rena, Blackthorn, and Cantina reports support twenty-six narrow modes:

| Failure mode | Published example | Report status |
| --- | --- | --- |
| Inconsistent liquidation reward units | Size H-04 | Confirmed; fix reported |
| Delisting blocks existing collateral exits | INIT M-09 | Acknowledged |
| Residual debt lacks loss recognition | INIT M-10 | Confirmed |
| User withdrawal counters share a reset marker | prePO H-01 | Confirmed |
| Deposit credit exceeds net receipts | prePO M-02 | Confirmed; final severity Medium |
| Partial liquidation leaves residual dust | Morpho Midnight Cantina Solo 3.1.1 | Documented; won't fix |
| Offer fills fragment borrower debt below recovery size | Morpho Midnight Cantina Competition 3.1.5 | Acknowledged |
| Fixed-index liquidation uses stale collateral | Morpho Midnight Cantina Competition 3.1.8 | Mechanism acknowledged; impact qualified |
| New credit enters a terminal loss state | Morpho Midnight Blackthorn M-1 | Resolved; fix reported |
| Allocator deposits into a vault with unresolved losses | Bitcorn Cantina Managed 3.1.1 | Fix verified by auditor |
| Pausing an adapter blocks repayment | Bitcorn Cantina Managed 3.2.1 | Fix verified by auditor |
| Expired rate schedule omits earned interest | Morpho Vault V2 Cantina Competition 3.1.1 | Published; no disposition in report |
| Stale adapter allocation understates loss | Morpho Vault V2 Cantina Competition 3.1.2 | Published; no disposition in report |
| Net profit estimate counts an adapter loss twice | Morpho Vault V2 Cantina Competition 3.1.3 | Published; no disposition in report |
| Public model update trusts caller-supplied market state | Silo Finance Cantina Dynamic Kink review | Fixed reported; High |
| Pending rate configuration mutates live state | Silo Finance Cantina Dynamic Kink review | Fixed reported; Medium |
| Arbitrary recipient actions refresh a target restriction | InfiniFi Cantina review | Fixed; Cantina Fix OK; High |
| Same-epoch state transition earns rewards in both states | InfiniFi Cantina review | Fixed; Cantina Fix OK; High |
| Sequential allocation mutates the shared denominator | InfiniFi Cantina review | Fixed; Cantina Fix OK; High |
| Cancellation subtracts a scheduled delta before application | InfiniFi Cantina review | Fixed; Cantina Fix OK; High |
| Partial settlement rounds liability reduction down | InfiniFi Cantina review | Fixed; Cantina Fix OK; Medium |
| Privileged operator bypasses delegated beneficiary routing | Telcoin Tn Contracts Cantina review | Fixed reported; High |
| Live-count bounds skip sparse monotonic identifiers | Telcoin Tn Contracts Cantina review | Fixed reported; High |
| Terminal penalty path refunds an uncleared balance | Telcoin Tn Contracts Cantina review | Fixed after policy change; High |
| Epoch settlement mixes parameters from different versions | Telcoin Tn Contracts Cantina review | Fixed reported; Medium |
| Validator registration accepts a reused consensus key | Telcoin Tn Contracts Cantina review | Fixed reported; Medium |

The graph contains 62 nodes and 85 edges. `specializes` connects narrower modes
to broader categories, `violates` links modes to properties, and `instance_of`
connects historical findings to modes. The liquidation reward mode has both an
accounting parent and a liquidation parent. These relationships are Cimices's
curation, not labels supplied by Code4rena or OWASP.

```sh
cimices explore data/protocols.json gpt-4o 4096 full 5 2 "liquidation reward" --compact
cimices instances data/protocols.json bm25 gpt-4o 4096 full "withdrawal" --compact
cimices resolve data/protocols.json gpt-4o 4096 full mode:delisted-collateral-exit finding:c4:init-m09 --compact
```

Mode records describe root cause, applicability, exclusions, and corrective design
principles. Finding records retain report severity and sponsor disposition separately
from Cimices's `source_checked` status. A reported fix is not independent verification
of that fix. Findings describe historical audit scopes, not current deployments.

INIT M-09 specifically preserves the report's qualification: under the sponsor's
stated delisting sequence, the remaining issue is blocked withdrawal. It is not
classified here as demonstrated liquidation denial of service.

Each citation identifies a report section and includes a SHA-256 digest of the
observed HTML response or complete PDF. Morpho PDF URLs pin the GitHub commit
`55995f27dd4afb8a61e99cd160c7b3a4afc67e54`; the Morpho Vault V2 Cantina PDF
pins `a0ba9df0ea697a080c0de69c18b84738cfb3bef7` and covers audited commit
`5938a924`. Bitcorn's Cantina PDF and the Silo, InfiniFi, and Telcoin Cantina pages
are hosted at mutable URLs. Raw report snapshots are retained locally during
curation and are not redistributed in the repository. Original issue and fix links
are retained as mappings. Telcoin's five mapped fix commits resolved during curation.
The five InfiniFi commit links cited by its report returned HTTP 404, so those mappings
preserve the report's fix references but are not independent evidence that the commits
remain publicly accessible. No report code or reproductions are bundled. See
[attribution](../data/ATTRIBUTION.md).

This corpus is separately selectable. It does not modify OWASP source records or
automatically add new classes to the SCWE planner catalog. Existing authored
retrieval diagnostics are not independent evaluation of these new records.
