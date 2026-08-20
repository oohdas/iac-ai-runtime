# IAC AI Runtime — Repository Handoff

## Exact destination

- Owner: IAC company account or organization
- Repository name: `iac-ai-runtime`
- Visibility: private
- Initialization: empty; do not add a README, `.gitignore`, license, or template
- Default branch after push: `main`

## Verified source

- Local release commit: `fb62e79`
- Canonical release command: `python3 scripts/verify_release.py`
- Runtime tests: 68 passing
- Recovery drill: passing
- Bridge contract hash:
  `70f271353b4e6696ada8816f6bad821cfabaec4e87aa96edaae97a14ac7f41d8`
- Working tree: must be clean before push

## Automatic checks after publication

Every push and pull request will run the read-only `Verify IAC Runtime` workflow.
It compiles the code, runs all tests, performs a recovery drill, verifies the
ownership bridge and container safety invariants, and builds—but does not
publish—the container.

## Authority boundary

Creating the repository and pushing this commit authorizes source publication
only. It does not authorize:

- Railway service or volume creation;
- deployment or public network exposure;
- production credentials or secrets;
- paid model/API usage;
- live Claude, email, calendar, ShopVox, QBO, QNAP, or RBC connections;
- customer contact, external record mutation, deployment handlers, or money movement.

Each production capability remains separately approval-gated.
