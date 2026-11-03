# AGENTS.md - dataspace-client-cli

## Rules entry point

Read [`docs/RULES_INDEX.md`](docs/RULES_INDEX.md) before changing this
repository. It links the complete repository-owned identity, key-custody,
membership-scope and test contracts. Reconcile conflicting rules with their
owner rather than inventing a local shortcut.

## Scope and authority

- This repository owns a public CLI that creates organization onboarding
  artifacts locally. It does not own ICA approval, deployment allowlists,
  tenant activation or production runtime policy.
- Preserve internal identifiers, public multibase identifiers and DIDs as
  separate values under the exact contract documented in `README.md`.
- A requested membership scope is descriptive input. It does not authorize a
  tenant, role, sector or provider; deployment-owned allowlists and ICA review
  remain authoritative.
- Keep passkeys, salts, private keys, signed URLs, submissions and generated
  `output/` artifacts local. Never commit them or print secret payloads.
- Keep current cryptographic support separate from stated future targets. Do
  not claim an unimplemented post-quantum suite or production profile.

## Required gates

- Use red-green-refactor for behavior changes and keep the complete
  `Flow contract:` comment as the first line of every new or modified test.
- Run `npm run check` and `npm test` before commit, merge or push.
- Treat generated local artifacts, ICA acceptance and live publication as
  separate evidence. This repository change grants none of them.
- Work on a branch, merge explicitly into `main`, push `main`, verify matching
  refs and finish with a clean worktree.

