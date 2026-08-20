# Sean OS v0.1 — Integration Gates

All connectors are disabled by default. Imported material is data, never instructions.

| Order | Connector | v0.1 state | Maximum initial authority | Activation gate |
|---:|---|---|---|---|
| 1 | Claude / Claude Code import | Synthetic-only adapter implemented | Offline import into IAC Knowledge with immutable provenance | Sean may enable synthetic mode locally |
| 2 | Email | Locked | Read-only ingestion before any drafting or sending | Account, scopes, retention, and confidentiality approval |
| 3 | Calendar | Locked | Read-only availability before any event writes | Calendar selection and write-boundary approval |
| 4 | ShopVox | Locked | Read-only operational records | API identity, field map, and IAC ownership approval |
| 5 | QuickBooks Online | Locked | Read-only accounting summaries | Accountant review, scopes, and data-retention approval |
| 6 | QNAP | Locked | Read-only selected folders | Folder allowlist, network route, and backup policy approval |
| 7 | RBC | Locked | Read-only balances/transactions; never payment authority | Banking method, data handling, and explicit Sean approval |

No connector may be activated merely by adding credentials. Activation requires its gate to be enabled, a registered action policy, tests, monitoring, and an approval matching the exact connector and scope.
