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

## LCW repository standard — 2026-09-11

This repository is governed by the owner-approved LCW security standard.

- The human owner is the final authority.
- LCW is the independent guardian and emergency-control layer.
- Default deny applies to security-sensitive and privileged actions.
- Destructive, billing, permission, secret, authority-changing, or security-weakening actions require explicit owner approval.
- Operational agents may not grant themselves additional authority, bypass LCW, disable auditing, or modify the controls that constrain them.
- LCW enforcement credentials and control paths must remain outside operational-agent write authority.
- Security failures and unverifiable security state fail closed.
- Secrets must never be committed, logged, returned to clients, or included in model context.
- Because this repository is public, only explicitly public material may be committed; production collector data remains prohibited.
- Production and security-sensitive changes require a reviewable pull request plus validated checks.
- Documentation is policy, not enforcement; controls must be implemented at repository, credential, deployment, network, and tool layers where applicable.

### GitHub assurance boundary

For repositories operated under GitHub Free, the required target is to use all security controls technically available to the current account. Any `100%` assurance statement is explicitly scoped to that available-control set and is not an absolute-security claim.

Provider-level protections that are unavailable under the current plan are not considered active merely because they are documented. Until stronger provider-enforced controls are available and independently tested, the human owner remains the compensating control by personally reviewing and merging security-sensitive pull requests after successful CI.

If required CI or equivalent validation is absent or failing, the repository is below the LCW standard for security-sensitive deployment and must fail closed.
