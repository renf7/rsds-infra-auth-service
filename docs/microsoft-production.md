# Public Microsoft sign-in

Jira: https://rsdsoftware.atlassian.net/browse/RSDSINFRA-31 (parent RSDSINFRA-8, SCRUM Sprint 0).

To accept personal Microsoft accounts and work/school users from any Microsoft
Entra public-cloud directory, register a **Web** application with supported account
types **Accounts in any organizational directory and personal Microsoft accounts**
(`signInAudience=AzureADandPersonalMicrosoftAccount`). Register this exact callback:

`https://www.rsdsoftware.eu/api/auth/login/oauth2/code/microsoft`

Keep local test registrations separate; the manual preview is only
`https://localhost:18443`. The app owner does not restrict the sign-in population.
Organization admin-consent and Conditional Access policies still apply. No guest
invitation or per-user application configuration is required by this service.

Set these entries in the private production provider configuration:

```ini
RSDS_AUTH_PROVIDERS_MICROSOFT_CLIENT_ID=<Application (client) ID>
RSDS_AUTH_PROVIDERS_MICROSOFT_CLIENT_SECRET=<client secret Value, not Secret ID>
RSDS_AUTH_PROVIDERS_MICROSOFT_TENANT=common
```

Only set `common` **after this change has merged and its main image has been
published and deployed**. Existing images reject that value. Refresh the provider
Kubernetes Secret and roll out auth with the new image; a Secret update alone does
not reload process environment variables. Preserve all other real provider settings.
Never commit credentials, print the Secret, or use a test account password as a
client secret. Keep the previous image and tenant configuration for rollback.

An explicit canonical lowercase tenant UUID remains supported for operators who
intentionally restrict login. The Microsoft consumer directory UUID
`9188040d-6c67-4c5b-b112-36a304b66dad` intentionally supports personal accounts only.
No extra Helm values or frontend changes are needed: the existing provider Secret
is already injected into auth and the frontend discovers enabled providers.

## Validation boundary

Common-mode authorization/token URLs use only `login.microsoftonline.com/common`.
Untrusted `tid` must be a canonical UUID and `iss` must equal
`https://login.microsoftonline.com/<tid>/v2.0` exactly. Signing keys come only from
Microsoft's fixed common JWKS URL (redirects disabled), and their `issuer` metadata
must match that issuer or Microsoft's `{tenantid}` template. RS256 signatures,
required OIDC claims, client audience/authorized party and timestamps are validated.
Spring's OIDC provider still validates authorization state and nonce; PKCE remains
enabled. Key caching is shared and bounded by a single JWKS document, with expiry
and rate-limited key-rotation refreshes; no tenant-indexed unbounded decoder cache
or token-directed network lookup is used. Sovereign clouds are not included.

Internal accounts continue to use provider + actual issuer + immutable subject;
equal subjects in different tenants are separate identities. Email is not collected
or used for automatic linking, and provider claims cannot assign internal roles.

Tests use signed local provider-boundary data, not real Microsoft accounts. Existing
database/API contracts exercise real DynamoDB Local and internal JWTs. Production
acceptance must separately sign in with a personal account and an authorized
work/school account, refresh the browser, inspect the avatar/Settings and log out.
Passing automated tests does not claim live-provider or organizational consent coverage.

References:
- https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens
- https://learn.microsoft.com/en-us/entra/identity-platform/howto-convert-app-to-be-multi-tenant
