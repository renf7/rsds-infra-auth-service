# ADR: shared NoSQL persistence boundaries (RSDSINFRA-15)

Status: foundation implemented; future service adapters remain acceptance work.

## One database and service ownership

Keep exactly one DynamoDB table, keyed by string `pk`. Existing auth:v1 keys and
provider bindings remain unchanged: this change performs no account migration.
New service repositories can compose the vendor-neutral DocumentStore through
ScopedDocumentStore(service, tenant). Its scope:v1 prefix encodes service, tenant
and logical key separately using unpadded URL-safe Base64 of valid UTF-8. Delimiters
and Unicode cannot escape boundaries. Components are nonblank and <=256 Java chars;
the complete encoded key is additionally checked against DynamoDB's 2048-byte limit
before any adapter call. Values remain immutable
string maps. This is a persistence namespace, not an authorization mechanism:
services derive tenant from trusted JWT/server policy, never caller-supplied scope.

Keep the raw store private to composition roots. Service-owned repositories expose
use-case methods, not AWS clients or arbitrary physical keys. SDK types stay in the
Dynamo adapter. Auth owns identities/roles/session rows; offers owns offer/reply
history; competence owns plans. No cross-service joins or database transactions.
Existing auth is deliberately not wrapped retroactively, which would change keys.

## Portable subset and limits

The current port supports strong point reads, atomic insert-if-absent, and opaque
revision CAS replacement. Conditional failure returns false; transport/permission
errors propagate and must not be mistaken for conflicts. Retry an insert with the
same logical key; read the winner after a conflict. Retrying stale CAS never silently
overwrites a newer revision. Records own explicit schema versions in their values.

Scoped records deliberately reject insertExpiring/replaceExpiring through the port's
unsupported-operation defaults. Existing native TTL is restricted to legacy auth
transient namespaces; new scope:v1 services must design their own reviewed retention
policy before enabling physical expiry. Legacy auth retention remains unchanged.
No generic scan, filter DSL, SQL, secondary-index syntax, multi-row transaction,
delete or pagination capability is claimed. Future offer/competence access patterns
must define bounded owner-scoped list ports and opaque cursor semantics, indexes and
migration before implementation. Do not simulate pagination with a whole-table scan.
A second engine must contract-test exactly these atomicity/consistency guarantees;
changing host/port alone cannot translate different NoSQL protocols.

## Credentials and least privilege

Production uses EKS workload identity and region/table configuration; never local
fixture credentials or SDK endpoint overrides. Only auth receives signing private
keys. Resource services receive public verification material. IAM roles must restrict
GetItem/PutItem to the single table and service-owned physical key prefixes using
`dynamodb:LeadingKeys` conditions. A namespace wrapper alone is not an IAM boundary.
Existing auth permissions must preserve legacy auth:v1 prefixes until migration.
Future list adapters need a separately reviewed Query/index permission; never grant
Scan or unrestricted table access merely to implement a list UI.

## Migration and backup/restore

1. Inventory schema versions, existing key prefixes and source/target adapter contracts.
2. Enable production PITR/deletion protection through infrastructure management. Verify
   the configured restore window and retention with the operator; local in-memory
   DynamoDB intentionally does not prove production durability or backup recovery.
3. Restore a backup to an isolated table, never over the live table. Compare record
   counts by owned namespace, validate revisions/schema/identity bindings and replay
   adapter contracts against the restored copy using dedicated credentials.
4. For another engine, export authorized service-owned records, transform physical
   framing/indexes, retain internal account UUIDs/roles/avatar and schema versions,
   import idempotently, compare hashes/counts and test concurrent CAS behavior.
5. Freeze or reconcile writes during cutover; record rollback point and routing.
   Switch adapter/config only after contract and application E2E acceptance. Never
   infer migration success merely from a successful connection or row count.
6. Restrict exported backups, expire test copies, record restore evidence without
   copying provider secrets, JWTs or personal records to PR artifacts.

Auth contract tests run against the in-memory reference and actual DynamoDB Local.
They check conditional writes, stale revision rejection, immutable snapshots,
service/tenant isolation and competing insert/CAS writers. Browser tests use the
real auth/JWT/database with provider-boundary fixtures only. Production restore,
future service adapters/indexes/pagination remain explicit follow-up acceptance;
this auth-only PR must not close the entire cross-service ticket.
