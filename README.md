# rsds-infra-auth-service

Apple sign-in is disabled by default in both production and local fixtures
([RSDSINFRA-32](https://rsdsoftware.atlassian.net/browse/RSDSINFRA-32)): the owner
defers its annual Apple Developer membership cost until website profitability.
Stale Apple credentials do not enable it. Provider discovery reports Apple disabled,
and no Apple OAuth client is registered. The frontend also omits its button.
Retained isolated protocol tests explicitly set `RSDS_AUTH_PROVIDERS_APPLE_ENABLED=true`;
ordinary environments must leave it unset/false. Re-enablement requires an explicit
owner decision, paid membership, configuration and live-provider acceptance.

For personal and organizational Microsoft accounts without guest invitations, see
[public Microsoft sign-in configuration and validation](docs/microsoft-production.md).

Authentication backend for the one RSDS-INFRA frontend. Jira: [RSDSINFRA-16](https://rsdsoftware.atlassian.net/browse/RSDSINFRA-16), JWT/session RSDSINFRA-17, persistence RSDSINFRA-15, UI RSDSINFRA-19.

Baseline: Spring Boot 4.1.2, Java 27 (latest stable verified 30 October 2026), Spring Security-managed OAuth2/OIDC and JWT libraries. Public repository; free scanners only. Read [AGENTS.md](AGENTS.md) and the [repository standard](https://github.com/renf7/rsds-infra-helm/blob/main/docs/security/REPOSITORY-STANDARD.md).

The initial default branch is a compiled security/bootstrap baseline. Authentication feature work is reviewed on a dedicated PR; do not treat the bootstrap as a complete auth implementation. Provider app registrations are not supplied. Local protocol fixtures never establish live-provider acceptance.

Build with Java 27: `sh mvnw verify`. Docker build requires no host Java/Maven. The committed Maven 3.10.0 wrapper validates its distribution SHA-256 (upstream SHA-512 verified during bootstrap). Never commit signing keys/provider credentials.

All backends must use current stable Java/Spring Boot and this baseline: CodeQL, Semgrep CE, Trivy, Sonar public quality gate, dependency checks/Dependabot, secret protection, compiled SpotBugs + Find Security Bugs. Actual scan evidence and native settings must be verified, not inferred from YAML.

## Local end-to-end usage

Use the [rsds-infra-local runbook](https://github.com/renf7/rsds-infra-local/blob/RSDSINFRA-25-local-testing/README.md). Until the linked PRs merge, select auth #1, frontend #17, Helm #9 and runner #1. The local runner builds all four exact PR heads and supplies one DynamoDB Local instance plus a protocol fixture. It generates RSA-3072 application signing material and an independent P-256 Apple client key itself; no host Java, Python, OpenSSL, provider account or production/cloud credentials are required. E2E is disabled unless explicitly requested.

```powershell
.\out\rsds-local.exe up --docker-context desktop-linux --manifest local-test-auth.json --pr rsds-infra-auth-service=1 --pr rsds-infra-company-page=17 --pr rsds-infra-helm=9 --pr rsds-infra-local=1 --e2e --port 18091 --cluster rsds-local-auth-review --workdir .local-auth-review
.\out\rsds-local.exe status --workdir .local-auth-review
.\out\rsds-local.exe down --workdir .local-auth-review
```

Run these from the runner repository, not this service. Substitute your actual local Docker context; Linux/macOS use `./out/rsds-local`. After all changes merge, omit PR overrides to select the actual default branches. Do not do that while defaults contain only the bootstrap.

The enabled suite contains 44 tests: original 16 marketing behaviors plus 28 auth scenarios. The fixture is only the external provider boundary: actual browser navigation, code/token/userinfo requests, OIDC signatures/nonce, PKCE where supported, Apple's form_post, Spring callbacks, first-party JWT signing/validation, cookies, database writes and refresh/logout execute normally. Invalid provider signatures, denied consent, forged state, tampered application JWT, CSRF rejection and refresh replay are checked. No application login/JWT/session response is intercepted. Country lookup alone remains mocked as before. Report mode `local-protocol-fixture` explicitly distinguishes this from live-provider verification.

Live provider app registrations are not configured. Test user accounts alone are insufficient for live acceptance. Before production, independently verify all five live providers, their registered HTTPS callbacks, consent/MFA/account restrictions, Microsoft tenant policy and Apple first-login data behavior. Local passing tests do not establish those results. Production never enables the local profile or test identity provider.

## Browser and API contract

| Endpoint | Behavior |
| --- | --- |
| GET `/api/auth/providers` | Registered/enabled providers; no client secrets |
| GET `/api/auth/oauth2/authorization/{provider}` | Starts server-managed authorization-code flow |
| GET/POST `/api/auth/login/oauth2/code/{provider}` | Spring callback; Apple uses POST with validated one-use state/nonce |
| GET `/api/auth/session` | Anonymous `{authenticated:false}` or current trusted identity/roles |
| GET `/api/auth/me` | Requires a valid first-party JWT and persisted identity |
| GET `/api/auth/csrf` | Generates CSRF cookie and header token |
| POST `/api/auth/refresh` | CSRF protected; rotates opaque refresh token, rejects replay and revokes family |
| POST `/api/auth/logout` | CSRF protected; revokes refresh family and clears cookies |
| GET `/api/auth/.well-known/jwks.json` | Public verification keys only; never private material |

The browser receives `RSDS_ACCESS` (HttpOnly, Secure in production, SameSite=Lax, 300 seconds, path `/`) and `RSDS_REFRESH` (opaque, HttpOnly, Secure, seven-day maximum, path `/api/auth`). JWTs/provider tokens never enter redirect URLs, browser local/session storage or API response bodies. `login=success/failed` is a status flag, not a token. Refresh/logout send the token from `/csrf` as `X-XSRF-TOKEN`. OAuth session cookies are HttpOnly/Secure/SameSite=None in production to support Apple's cross-site form POST; local same-origin fixtures explicitly use HTTP/Lax. Provider tokens are discarded with the temporary OAuth session after sign-in. Access tokens already issued remain cryptographically valid for at most five minutes after logout/role change for offline resource services; do not claim instantaneous distributed JWT revocation.

Internal accounts are resolved by **provider + issuer + immutable provider subject**. Each new provider identity receives an opaque internal UUID and no privileged roles. Email is never a login requirement, uniqueness index or automatic linking key, even if the provider marks it verified. Matching emails/names across providers create separate new accounts. JWTs contain the UUID, stored roles and validation claims; no email claim. No application email-code prompt is part of sign-in.

Request minimal profile scopes and discard incidental provider email claims. GitHub uses `read:user` without `user:email` or `/user/emails`; Facebook requests `public_profile` and `id,name`. Google/Microsoft use `openid profile`, Apple `openid name`. Optional contact email is entered by the user in Settings, protected by JWT and CSRF, and never links accounts or grants roles.

Existing v2 provider bindings/account UUIDs, roles and persisted avatar colours are preserved, including accounts historically shared across providers. New logins never add a provider through an old email index. Do not silently split legacy shared accounts, duplicate privileges or delete account data. New records use schema 3 while retaining the existing portable index format for compatibility. Explicit account linking and legacy account separation/recovery require a separately designed proof-of-control workflow; they are not implemented by this change. See [the identity ADR](docs/architecture/provider-identity.md). Legacy email-code endpoints are retained for compatibility but no provider callback creates a pending challenge and completion cannot link by email.
OAuth handshakes currently require one replica or a shared session/sticky strategy before scaling.


## Production configuration and certificates

### Real providers with local infrastructure

Set `rsds.auth.provider-mode=live` (`RSDS_AUTH_PROVIDER_MODE=live`) independently of the `local` profile. The local profile still supplies DynamoDB Local, throwaway signing material and local cookie settings; it no longer forces provider fixtures when explicitly set to live. Omitted providers remain disabled, with no automatic fixture fallback. `fixture` is rejected outside local infrastructure. Use the runner's `--provider-config` option described in its README; automated `--e2e` is forbidden in live mode.

Real providers require application-owner OAuth app registrations, approved exact callbacks and protected client credentials even when test user accounts already exist. Never supply provider account passwords to this service. Google/GitHub/Microsoft GET callbacks can use provider-approved loopback development URLs; Facebook development settings may require HTTPS/domain setup. Register the exact origin/path accepted by that provider. Apple form POST requires the production HTTPS/Secure-cookie profile and registered domain; local HTTP live Apple fails explicitly rather than claiming working support.

For personal Outlook accounts, configure an app allowing personal Microsoft accounts and the explicit consumer tenant UUID `9188040d-6c67-4c5b-b112-36a304b66dad`; unrestricted `common` is still rejected. Reference: https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens . A tenant UUID alone does not register an application.

### Stable account avatar

The account stores one randomly selected dark background from a fixed white-text palette. It is retained on repeat login/restart of the same internal account; separate new provider accounts have independent colours. Legacy records receive a colour once through atomic CAS. Session/profile responses include `initials` and `avatarColor`; no JWT secrets are exposed. Initials use the first and last name's first letters, or the first two letters of a single-word name; a missing second letter uses U, and no usable name uses UU. Uppercase Unicode letters are supported. Local in-memory DynamoDB data is intentionally lost on teardown; production persistence retains the colour.

### Database connection portability

Connection properties are external: `rsds.auth.region`, `table`, and (local adapter) `dynamo-endpoint` (host/port URL). Production DynamoDB uses the AWS SDK credential chain/workload identity, not a database username/password. Domain code depends only on `DocumentStore` strong-read/conditional-insert/CAS operations. Other NoSQL protocols need an adapter implementing those contracts and a data/index migration; changing host/port/user/password alone cannot convert DynamoDB requests into MongoDB/Cassandra/etc. Do not put database or OAuth credentials in application properties committed to Git.

Provide an existing shared DynamoDB table, scoped AWS workload identity (SDK default credential chain, STS included), signing/trust mounts, provider app registrations and canonical public base URL. No production credentials are hardcoded. Helm auth defaults disabled; it requires signing/trust secret names before enabling.

| Configuration | Required value |
| --- | --- |
| `RSDS_AUTH_PRIVATE_KEY` | Path to mounted PKCS#8 RSA private PEM, default `/run/signing/private.pem` |
| `RSDS_AUTH_PUBLIC_CERTIFICATES` | Directory of pinned `.crt` X.509 public certificates, default `/run/trust` |
| `RSDS_AUTH_TABLE`, `RSDS_AUTH_REGION` | Existing shared table and region |
| `RSDS_AUTH_PUBLIC_BASE_URL` | Exact HTTPS origin, e.g. `https://www.rsdsoftware.eu`, without trailing slash |
| `RSDS_AUTH_PROVIDERS_<PROVIDER>_CLIENT_ID` | Provider's registered application/Services ID |
| `RSDS_AUTH_PROVIDERS_<PROVIDER>_CLIENT_SECRET` | Required for Google/Microsoft/GitHub/Facebook; not Apple |
| `RSDS_AUTH_PROVIDERS_MICROSOFT_TENANT` | Explicit permitted tenant UUID; unrestricted `common` is rejected |
| `RSDS_AUTH_PROVIDERS_FACEBOOK_GRAPH_VERSION` | A supported registered Graph API version such as `v25.0`; review current provider lifecycle |
| `RSDS_AUTH_PROVIDERS_APPLE_TEAM_ID`, `_KEY_ID`, `_PRIVATE_KEY_FILE` | Apple team/key identifiers and mounted PKCS#8 EC `.p8` key |

Register exactly `https://www.rsdsoftware.eu/api/auth/login/oauth2/code/{provider}` (or your configured canonical origin) with each provider. Apple requires its Services ID/domain/return URL configuration; a fresh ES256 client-secret JWT is generated for each token exchange, never a stale baked-in secret. OIDC issuer/audience/signature/nonce checks use Spring Security. GitHub/Facebook use verified server-to-server userinfo with the returned access token. Configure no wildcard callback/return URLs.

The authentication service alone mounts the RSA private signing key. Every backend mounts the same **public-only** trust certificate bundle. A matching, currently valid RSA X.509 certificate is required at startup; `kid` is its SHA-256 fingerprint. Decoding pins RS256, internal keys, issuer `https://www.rsdsoftware.eu/auth`, audience `rsds-infra`, timestamps, subject and jti. Never trust a JWT-provided URL/key. Rotation: distribute old+new public certificates to every resource service first, switch auth's private key to the new matching certificate, keep overlap for the maximum issued-token lifetime and rollout window, then remove retired keys. Restart services to reload the mounted bundle; hot reload is not implemented. Local certificates expire after 48 hours; use a fresh owned local run afterward. Production key lifecycle/storage/backup is an operator responsibility, not the local fixture generator.

## Portable NoSQL contract

`store/DocumentStore` exposes immutable string-keyed documents, strong reads, insert-if-absent and revision-based atomic compare-and-set. Domain identity/refresh services import no AWS types. The Dynamo adapter owns all SDK/query/conditional-write details; a reference adapter and real DynamoDB Local execute the same contract tests. One shared table uses `auth:v2:email:*`, `auth:v2:account:*`, `auth:v2:binding:*`, `auth:v2:pending:*`, rate-limit namespaces, and `auth:v1:refresh:*`. Other services must use their own namespaces, credentials and API boundaries. No cross-service joins are assumed.

Another engine needs an adapter that preserves strong reads, uniqueness and CAS semantics, the same contract tests, schema/data conversion and access-policy migration. This is portable architecture, not a claim that any NoSQL product can be swapped by changing a connection string. Refresh records retain only token hashes/family state and expiry; application checks enforce expiry independently of database cleanup. Arrange expired-record retention cleanup/backups and restore exercises before production. DynamoDB Local uses one ephemeral in-memory database; `down` removes it. Production never uses that fixture database or its local dummy credentials.

## Verify the service itself

Start DynamoDB Local (only loopback port 8000) and set `TEST_DYNAMO_ENDPOINT=http://127.0.0.1:8000`, then run `sh mvnw verify` with Java 27. CI does this automatically and requires real adapter/HTTP integration tests; without the variable those specific integration tests are skipped and must not be reported as verified. Other unit/security tests run without a database. Tests create temporary keys; no test private key is committed. JaCoCo and SpotBugs XML reports are under `target/`.

Narrow SpotBugs `EI_EXPOSE_REP2` constructor annotations document intentionally shared injected store/client/cookie-writer references; they do not hide crypto/CSRF findings or disable rules globally. Review these exceptions whenever those dependencies change (review by 28 January 2027). All other findings/errors block verification. Native secret scanning/push protection and Dependabot features are configured separately from YAML. Sonar project key is exactly `rsds-infra-auth-service`, public in organization `renf7`, always enabled, with `SONAR_TOKEN` only in Actions secrets. Forks never receive it. PR jobs do not publish/deploy.


For production Apple, set Helm auth.appleKeySecretName to a private Secret containing apple.p8 (mounted only into auth). For local testing the runner generates a throwaway P-256 key; the fixture receives only its public key and verifies the actual ES256 client-secret JWT, including issuer/subject/audience/expiry. There is no local shortcut around Apple client-secret signing.


Sonar rule S4502 is narrowly annotated on configureAppleCallbackCsrf only: Apple's external form_post callback cannot supply the application's CSRF token. The exact POST callback instead requires Spring's session-bound, one-use OAuth state and OIDC nonce; every other unsafe request retains CSRF validation. Real HTTP tests reject forged Apple state, other provider POST callbacks, callback subpaths, and refresh/logout without CSRF. This protocol exception has a 28 January 2027 review date; it is not a general CSRF exclusion or relaxed gate. The CSRF cookie itself is HttpOnly; the UI obtains its header token from the same-origin /csrf endpoint.

Email verification API: GET /api/auth/email-verification returns only masked status for the pending cookie; POST /api/auth/email-code accepts an address only when missing; POST /api/auth/verify-email consumes the emailed code and issues HttpOnly cookies. Both POSTs require CSRF. Production SMTP uses SPRING_MAIL_HOST/PORT/USERNAME/PASSWORD and RSDS_AUTH_MAIL_FROM; never put them in the frontend. Local-only Mailpit has no external relay and its API is exposed under /__test/mail/ only in the local auth chart. It stores disposable messages on a bounded memory-backed volume, never application identities. The shared NoSQL database remains DynamoDB.


Anonymous GET /api/auth/session reports refreshAvailable as a boolean cookie-presence hint only. It does not validate that cookie or grant authentication. The UI may try one CSRF-protected refresh, then reload the session; invalid/revoked refresh credentials still return 401. This also covers browser removal of an expired access cookie. No token values are exposed in session JSON.

Missing-email sign-in and Settings (4 November 2026): absent provider email signs in immediately using an immutable provider binding, without an email modal. New provider-bound rows share the existing portable DocumentStore and DynamoDB; existing verified-email account indices are unchanged. JWT subjects/roles are still server-controlled. GET/PUT /api/auth/settings requires JWT cookies; PUT also requires CSRF and only changes optional contactEmail. Contact email never creates/reassigns an email-identity index and does not grant verified ownership. Full-page EN/PL Settings routes are served by the React frontend. Provider-supplied unverified email retains existing ownership verification before email linking. Full-stack fixture suite now has 46 tests. Resource-server bearer defaults must not skip CSRF for cookie-authenticated mutations: a final CsrfFilter matcher preserves protection for all unsafe methods except the existing exact Apple form_post callback.


SSO update (6 November 2026): successful provider authentication immediately signs in or creates an internal account, with no application email-code popup for any provider. Existing immutable provider bindings are reused. Ownership-verified emails may share an account; unverified or absent emails use a separate stable provider/issuer/subject identity and never silently link another account. Optional email remains available on the full Settings page. Provider consent/MFA is unchanged. Automated provider coverage uses only local protocol fixtures; live acceptance is manual. This supersedes older email-code onboarding instructions above.

## Runtime provider visibility
Set RSDS_AUTH_PROVIDER_VISIBILITY_FILE to a read-only projected ConfigMap file containing a comma-separated allowlist (facebook,microsoft,google,github). The file is reread per discovery request; no restart needed. Empty, invalid or missing configured files hide all buttons. Without a configured file, supported registered providers are visible. Apple stays deferred. The API adds visible alongside enabled and returns Cache-Control: no-store. Visibility is presentation only: direct OAuth URLs, in-flight callbacks and existing JWT sessions are unaffected. See the Helm docs/provider-visibility.md runbook.
