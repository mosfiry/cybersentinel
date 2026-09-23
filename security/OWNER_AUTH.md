# Owner authentication

CyberSentinel supports a username/password Owner account while retaining `OWNER_TOKEN` as a migration-compatible legacy channel. Both channels must converge on the existing `OwnerSession`, `OwnerAuthenticationEvidence`, and mission authorization snapshot flow; neither channel grants tool, scope, network, credential, or policy authority by itself.

## Bootstrap

On first setup, call `security.owner_credentials.bootstrap_owner` with the bootstrap password supplied out-of-band, or provide it through `CYBERSENTINEL_OWNER_BOOTSTRAP_PASSWORD`. The default username is configured through `CYBERSENTINEL_OWNER_USERNAME` and defaults to the deployment’s Owner username. Bootstrap fails closed after the first credential record exists. The password is immediately converted to a salted `scrypt` verifier and is never persisted or returned.

The credential record stores only the verifier, algorithm/version, creation and update timestamps, and a monotonically increasing credential version. The runtime state file is ignored by Git and is written with mode `0600`.

## Login and rotation

Normal login calls `security.owner_credentials.authenticate(username, password)`, then creates an `OwnerSession` bound to the authenticated username and credential version. A new device uses the same username/password flow and receives a new session; device metadata is not the identity.

Password or username changes require a valid authenticated session proof and re-authentication. Rotation increments the credential version and invalidates the affected old sessions. A new login is required after rotation. Invalid, empty, expired, replayed, or unknown credentials fail without revealing which credential component was incorrect.

## Migration

Existing token callers remain supported during migration. Token-authenticated sessions use a non-secret legacy identity marker and continue through the same downstream session/evidence/authorization chain. New deployments should bootstrap the account and migrate callers to username/password; the token can then be removed from deployment configuration after compatibility callers are retired.

## Evidence boundary

`SUPPORTED` is an analysis status meaning that an evidence record is linked to a case according to the current analytical rules. It is not trusted instruction, Owner authority, execution authorization, scope expansion, or policy approval. External statements remain intact for analysis and traceability while their metadata remains `source=EXTERNAL_UNTRUSTED` and `authority=NONE`.
