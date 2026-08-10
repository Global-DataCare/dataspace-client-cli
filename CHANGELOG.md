# Changelog

## Unreleased

- Expanded the client CLI flows, configuration handling and integration
  documentation.
- Replace the historical hard-coded membership scope catalog with the shared,
  extensible `<service-category>:<membership-profile>` contract.
- Reuse `gdc-common-utils-ts` for scrypt profile parsing and RFC 7638 JWK
  thumbprints without changing existing service or Pontus-X key derivation.
