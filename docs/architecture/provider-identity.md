# Provider identity and email-free internal JWTs

Approved in RSDSINFRA-11 on 10 November 2026. This supersedes verified-email
uniqueness and mandatory email-code onboarding in earlier design notes.

The login key is the validated provider, issuer and immutable provider subject.
New bindings resolve an atomically inserted provider-account record containing
an opaque UUID, name, server-managed roles and permanent avatar colour. Strong
reads, conditional inserts and CAS stay behind DocumentStore; DynamoDB remains
the supported shared database adapter. A retry repairs missing account/binding
indices using the same deterministic provider record, without duplicating roles.

Internal JWTs contain UUID sub, roles, issuer, audience, iat, exp, jti and a pinned
certificate key ID. Neither email nor provider credentials are JWT identity.
Provider signature/state/nonce/PKCE validation, HttpOnly cookies, CSRF, short
access lifetime and rotating refresh credentials remain unchanged.

Request only login/profile scopes. Never call GitHub /user/emails or request
Facebook's email field. Discard incidental provider email claims. A user may
enter contact email in authenticated Settings; it is unverified contact data,
never an identity index, entitlement or account-linking proof.

Different provider identities create separate new accounts, even for matching
verified emails. Preserve existing v2 bindings, UUIDs, roles and avatar colours;
legacy email-indexed records remain readable and are not silently split,
reassigned or deleted. The existing account index field emailKey is retained as
a compatibility pointer to the account record, including provider-based ones.
New schema-3 accounts do not create or query the email uniqueness index.

Legacy code-verification endpoints are not initiated by provider callbacks and
cannot restore email-based linking. They can be retired separately with the
remaining compatibility code. Explicit account linking, legacy account splitting
and recovery need a separate authenticated proof-of-control design; none is
silently inferred or implemented here. Session preference/countdown is RSDSINFRA-28.

Acceptance: provider separation, concurrent repeat login, crash retries, legacy
binding preservation, server-only roles, optional contact persistence, minimal
scopes, no private email HTTP calls and email-free signed JWTs. Automated browser
acceptance uses only local provider-boundary fixtures with real app/JWT/DynamoDB.
Live-provider sign-in remains an independent manual test.

The broader RSDSINFRA-11 job/competence contracts remain pending those services.
