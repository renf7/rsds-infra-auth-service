# RSDSINFRA-18 + RSDSINFRA-42

The auth API explicitly allowlists public routes and denies unknown routes. Settings
and current-account reads use only the validated JWT subject; clients cannot choose
another account ID. PinnedJwtVerifier accepts a public `.crt` trust directory,
issuer and audience without loading signing private keys. Only RS256 and known
certificate fingerprints are accepted; issuer/audience/time/required identity claims
are checked. Rotation uses overlapping certificates: add old+new public certs,
roll out verifiers, switch auth signer, wait out old tokens, then remove old trust.
Trust is loaded at startup: certificate changes require a controlled rollout.

Future job/competence repositories must install this pattern with their own audience,
explicit JOB_REPLY/COMPETENCE_BUILDER role checks and subject-based ownership queries.
Do not give them the signing private key. Machine offer reads need a separate
machine audience/scope and explicit user ownership context. These service-specific
controllers/credentials are not fabricated in the auth repository and remain
RSDSINFRA-18 acceptance work when those services are implemented.

## Retention and application expiry

DocumentStore supports optional deletion metadata separately from document fields.
DynamoDB stores it as top-level numeric epoch seconds `authDeleteAfter`. Permanent
accounts/bindings and other service namespaces never receive this attribute.
Refresh families expire for use after seven days; replay/revocation evidence stays
until original expiry plus `RSDS_AUTH_REFRESH_RETENTION_SECONDS` (default one day,
allowed 1–30 days). Rotation/revocation preserves that deadline; expiry checks
continue even if the physical row remains. Pending email flows and mail throttles
retain one day after their independent logical expiry. Ordinary atomic replacements
preserve TTL. Tests use a controlled clock and real DynamoDB adapter contracts;
DynamoDB Local does not simulate physical TTL deletion.

An adapter for another NoSQL vendor must implement expiry metadata and an equivalent
cleanup process; unsupported adapters fail rather than silently ignoring retention.

## Operator rollout (not performed by this PR)

Confirm table ownership and existing TTL configuration before changing a shared table:

```bash
aws dynamodb describe-time-to-live --region eu-central-1 --table-name rsds-infra
aws dynamodb update-time-to-live --region eu-central-1 --table-name rsds-infra \
  --time-to-live-specification Enabled=true,AttributeName=authDeleteAfter
```

Do not replace another service's active TTL attribute without an agreed table-wide
migration. Application workload permissions remain GetItem/PutItem. TTL enablement
belongs to an operator. Verify numeric metadata on a disposable fixture before PROD.

`eu.rsdsoftware.auth.store.RetentionBackfill` is a separate operator CLI, never run
on application startup. Compile/package normally, construct the Maven runtime
classpath, then invoke with `region table private-checkpoint-file [--apply]`.
Without `--apply` it reports aggregate counts only and changes nothing. Each call
scans at most 100 evaluated rows. Review dry-run counts, then run with `--apply`;
repeat while `more=true`. A private checkpoint advances only when no CAS conflicts
occur. With conflicts, rerun the same page. Keep dry-run and apply on the same page.
The operator principal needs Scan and UpdateItem for this table, not the app role.
It modifies only the four transient prefixes, checks document revision and absent
TTL atomically, skips malformed/permanent/other-service rows, and gives already-old
rows at least another day before deletion eligibility. Cursor files contain keys:
store privately; no keys, tokens or documents are emitted to logs.

Monitor aggregate CLI counts, CloudWatch TimeToLiveDeletedItemCount and table storage;
investigate stalled cleanup separately from authentication. Physical deletion is
asynchronous and may take days. To pause cleanup, disable TTL using the operator
procedure; already deleted rows cannot be restored by disabling it. Keep PITR and
backup retention separate: backups can retain deleted personal data until their
own expiry. A rollback of application code does not remove existing TTL metadata.
Owner confirmation of production TTL and backup configuration is required before
closing RSDSINFRA-42. No production migration/deployment is included here.

AWS semantics: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/TTL.html
