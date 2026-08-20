# Sean OS v0.1 — First Production Decision

## Current status

The ownership split is approved and implemented. The Sean-owned personal control
plane is published to the private `seansadhoo/sean-os-personal` repository. This
IAC runtime remains local-only, has no remote, and is ready for an IAC-owned
private repository.

## Decision required next

Create or select the IAC-owned private repository `iac-ai-runtime`. This action
does not authorize Railway deployment, production secrets, spending, live data,
or external connectors.

## Recommended ownership split

1. **Sean-owned private repository** — personal Sean OS orchestration, PERSONAL configuration, and cross-domain control plane.
2. **IAC-owned private repository** — IAC worker, Revenue Agent, company integrations, and Railway deployment configuration.
3. **Versioned boundary** — the repositories exchange explicit commands/contracts; neither database contains the other's private records.

This preserves portability for a future IAC sale while keeping Sean's personal
control plane outside the sale boundary.

## Alternatives

- **Local-only for now:** preserve the current local Git repository and defer production. No continuous cloud runtime.
- **IAC-only pilot:** split and place only the IAC runtime in IAC GitHub/Railway. Personal Sean OS remains local and inactive. This advances IAC automation but is not the complete Sean OS production architecture.

## Explicitly not authorized yet

- Adding an IAC Git remote or pushing this source
- Creating a Railway service or volume
- Configuring production secrets, identity, monitoring, or spend
- Connecting live Claude, email, calendar, ShopVox, QBO, QNAP, RBC, or customer data
