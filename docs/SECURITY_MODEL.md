# CyberSentinel X 5.0.0 — Security Model

## Trust boundaries

- `BRIDGE_TOKEN` authenticates the local bridge transport only; it does **not** authenticate or identify an Owner. The bridge compares it with `hmac.compare_digest`.
- Owner authority comes from a live server-side session issued after username/password verification. Client-provided roles, booleans, owner IDs, or other claims do not create authority.
- Tool output, model output, search results, CVE records, and other external content are untrusted data. They cannot grant permissions or independently declare a mission goal complete.
- The bridge binds to `127.0.0.1` by default. A non-loopback bind requires an explicit configuration opt-in and a strong bridge token; the bridge itself is HTTP, so exposed deployments must provide an appropriately protected transport boundary.

## Owner credentials and session references

- Owner passwords are verified with scrypt. Only the password verifier and its parameters are persisted; password plaintext is not stored.
- Session bearer tokens are generated with high entropy and are accepted only at authentication boundaries. Persistent session rows and internal ownership bindings use the stable SHA-256 `session_reference`, not the bearer token.
- Session references are non-bearer identifiers, not substitutes for authentication. Resolution checks the backing session and account state, status, and expiry; logout/revocation invalidates the stored session row.
- The reference conversion is idempotent for already-hashed references. Database migration code converts legacy persisted bearer-token fields to references. New persistence paths and migrations must preserve this invariant: **never write a raw session bearer to SQLite, audit records, mission state, or logs**.

## Authorization and mission completion

- Owner authorization is bound to an immutable mission snapshot, request identity, target, allowed actions/tools, boundaries, and expiry. Queue workers revalidate the snapshot and the live Owner session before dispatch.
- Mission lifecycle operations enforce ownership using the authenticated session reference; possession of a mission ID alone does not authorize access or cancellation.
- Tool/model observations are not completion evidence. Completion is accepted only through deterministic, independent verification of the criterion. A tool's `criterion_id`, `success` flag, or self-authored evidence cannot establish goal completion.
- Mission reports trust only the explicit verifier authorities `deterministic_observation`, `deterministic_tool_result`, `project_test_process_exit`, `validated_status_snapshot`, and `persisted_watch_store`. Provider/model claims and unlisted authority labels remain unverified.
- Evidence records are integrity-protected and linked to the mission/request provenance. Failed or missing verification remains unverified; it is not converted to success.

## Network and SSRF controls

- Outbound requests in the model-provider and GitHub/NVD/MITRE provider paths use a DNS-pinned transport: the resolved address is checked before connecting, and the connection is made to that validated address rather than performing a second uncontrolled DNS lookup.
- Private, loopback, link-local, multicast, reserved, and otherwise non-public destinations are rejected by default. Loopback is an explicit exception for configured local model services; it does not authorize remote private-network access.
- Redirects are not followed, URL user-info is rejected, permitted schemes/ports are checked, and response/time limits are enforced. URL preflight alone is not the security boundary; the transport repeats validation at connection time.
- The process does not expose an arbitrary remote scanner or exploit runner. Any additional provider or URL-fetching code must use the same validated transport rather than a raw HTTP client.

## Container secrets and deployment boundary

- The Linux Compose target mounts its bridge token and provider API keys as read-only files under `/run/secrets/`; credential values are not passed as container environment variables or baked into the image. Runtime `*_FILE` reads reject a final-component symlink, require a regular file, and enforce a bounded UTF-8 read.
- The host setup helper creates secret files owned by root and group `10001`, mode `0440`; the application runs as UID/GID `10001:10001`. The mission worker receives provider keys but not the bridge transport token. Rootless Docker and user-namespace remapping are not validated for this release target.
- The one-shot workspace initializer has no network. The bridge and worker share a dedicated Compose bridge network, while only the bridge publishes a host-loopback port. Provider egress remains available. This is a single-host self-hosted target, not a public ingress or high-availability deployment, and it has no Cloudflare dependency.

## Workspace and process boundaries

- Workspace paths are first checked against the mission authorization snapshot. On POSIX, file operations then traverse directory descriptors relative to the opened workspace root, reject symlinks (`O_NOFOLLOW`), and use descriptor-relative rename/unlink operations. This closes the check-then-use path substitution window for the protected operations.
- Process working directories are pinned through an opened directory descriptor where supported. Process output is drained into bounded tail buffers, timeout handling terminates the process group, and audit records retain a command digest and executable identity rather than raw argument values.
- These controls govern CyberSentinel's workspace APIs; they are **not** an OS-level sandbox or a substitute for running untrusted code inside a separately restricted container/account. Platform fallbacks may provide weaker race guarantees than the POSIX descriptor-relative path.

## Audit and persistence

- SQLite records mission, request, authorization, execution, evidence, and lifecycle state needed for traceability. Sensitive bearer session values are represented by their SHA-256 references; passwords remain verifiers, and command arguments are not copied into workspace audit events.
- Session-reference migrations are security-sensitive. Backups, exports, and new structured fields must be checked so a legacy/raw bearer token is not reintroduced.
- The state archive is a versioned manifest plus per-file SHA-256 checksums. Backup rejects symlinks and non-regular files; verification checks every member before restore, and restore rejects traversal/link entries and requires an empty target directory rather than overwriting live state. The archive is not encrypted and can contain sensitive mission/workspace data; protect it accordingly. Compose credentials are stored separately and are intentionally outside the state volume/archive.
- Review `security/session_reference.py`, `security/owner_password.py`, `security/pinned_http.py`, `workspace/environment.py`, and the scheduled-worker authorization path when changing these boundaries.


## Release artifact provenance and limits

- The release builder binds `release-metadata.json` to the full source commit, versioned image tag, and image-archive SHA-256. The inner `SHA256SUMS` covers every payload file and the Docker image archive; the adjacent `.sha256` sidecar covers the outer bundle. CI also loads the saved Docker image and checks its OCI version label before uploading the candidate artifact.
- These checks detect accidental corruption and mismatched contents; SHA-256 files are not digital signatures and do not, by themselves, authenticate who produced an artifact. Obtain candidate artifacts from the expected exact-commit workflow run and review its checks before use.
- The workflow uploads an unpublished, expiring CI artifact only after tests and the isolated deployment rehearsal succeed. It does not publish to a registry, create a GitHub Release, deploy publicly, or create a final Git tag. Final release publication remains behind explicit Owner confirmation.
