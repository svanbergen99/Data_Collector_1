# Security boundary

This repository is designed as a deny-by-default collector runtime shell.

## Non-negotiable rules

- Never commit production data, credentials, API tokens, cookies, session material, private keys, encryption keys, database exports, internal endpoint inventories, recipient maps, or chain-position metadata.
- Assume the complete source code is known to an attacker. Security must not depend on hidden implementation details.
- Production cryptographic material belongs only in the deployment secret/KMS boundary, never in Git history or build artifacts.
- Each deployed collector must receive its own unique service identity/credential. Credentials must not be reused between collectors.
- A collector may know only the minimum input and output contract required for its own job.
- Root/master key material must never be present in a collector process.
- Data handling must fail closed on authentication, schema, freshness, destination, integrity, or replay failures.
- Logs must never contain plaintext protected payloads, credentials, authorization headers, cookies, keys, or decrypted secret material.
- Public ingress is forbidden unless explicitly required and separately reviewed.
- Health exposure is limited to `/healthz`; application/data routes must be added deliberately and covered by new runtime security tests before merge.

## Required checks

Every change must pass the repository security audit and runtime hostile-input regression tests. A local-only siege test is also included for controlled stress testing; it never accepts a remote target.
