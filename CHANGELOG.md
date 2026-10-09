# bedrock-aws-kms ChangeLog

## Unreleased

- Use `Uint8Array` for byte-oriented APIs.
- Rename the Bedrock configuration namespace to `aws-kms`.
- Construct named clients lazily without changing the synchronous
  `getClient()` API, and remove startup-time client pings.
- Add package and per-client Region configuration with IMDSv2 fallback.
- Add Nitro Enclave decrypt using the package-owned Alpine kmstool runtime.
- Preserve a bounded, credential-redacted kmstool stderr summary in KMS
  decryption errors so native failures remain actionable.
- Remove the production-only test client; tests configure it explicitly.
- Use `@digitalbazaar/http-client` for direct IMDS HTTP requests.
- Keep errors to standard names and actionable details instead of adding
  package-specific error codes.
- Return `NotSupportedError` for unsupported key types instead of throwing
  while reading the missing key configuration.

## 0.1.0 - 2026-04-xx

- See git history for changes.
