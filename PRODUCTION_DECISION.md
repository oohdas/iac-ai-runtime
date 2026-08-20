# Sean OS v0.1 — First Production Decision

## Decision required now

Choose the owner and destination for the local source repository before any remote is added or deployment begins.

## Recommended ownership split

1. **Sean-owned private repository** — personal Sean OS orchestration, PERSONAL configuration, and cross-domain control plane.
2. **IAC-owned private repository** — IAC worker, Revenue Agent, company integrations, and Railway deployment configuration.
3. **Versioned boundary** — the repositories exchange explicit commands/contracts; neither database contains the other's private records.

This is the cleanest option for a future IAC sale. It requires a Sean-controlled private source-control account or equivalent because none exists today.

## Alternatives

- **Local-only for now:** preserve the current local Git repository and defer production. No continuous cloud runtime.
- **IAC-only pilot:** split and place only the IAC runtime in IAC GitHub/Railway. Personal Sean OS remains local and inactive. This advances IAC automation but is not the complete Sean OS production architecture.

## Explicitly not authorized yet

- Adding a Git remote or pushing source
- Creating a Railway service or volume
- Configuring production secrets, identity, monitoring, or spend
- Connecting live Claude, email, calendar, ShopVox, QBO, QNAP, RBC, or customer data
