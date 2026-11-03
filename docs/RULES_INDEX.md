# Repository rules index

This index is the navigation entry point for rules owned by the public
onboarding CLI. It does not grant ICA, deployment or tenant authority.

## Repository authority

- [`AGENTS.md`](../AGENTS.md) defines scope, custody and required gates.
- [`README.md`](../README.md) defines the identifier, cryptographic,
  membership-scope, command and artifact contracts.
- [`.gitignore`](../.gitignore) defines local generated-artifact exclusions.
- [`package.json`](../package.json) owns the local `check` and `test` gates.

## Executable contracts

- [`test/scope-contract.test.js`](../test/scope-contract.test.js) protects the
  extensible service-category and membership-profile boundary.
- [`test/rules-links.test.js`](../test/rules-links.test.js) protects this rules
  graph.
- [`bin/client-cli.js`](../bin/client-cli.js) is the canonical CLI
  implementation; documentation must not claim unsupported commands or suites.

Private inputs and generated identity material remain outside Git. Public
documentation may describe their format but never records real operator data
or treats artifact generation as activation.

