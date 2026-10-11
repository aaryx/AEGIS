# Deployment and recovery

**Hardening update:** runtime DB privileges are provisioned separately from the
migration owner; `notifications` is a separate delivery service. Before this schema
upgrade, stop API/workers, back up, then run `docker compose up -d --build` to apply
migrations through revision 0004. The executable restore/outage drills and current
container findings are documented in [hardening.md](hardening.md).

## Local Compose

`python scripts/configure.py` then `docker compose up -d --build` starts PostgreSQL,
Redis, OpenSearch, migration/bootstrap initialization, API, worker and Next.js.
The optional `tools` profile provides a CLI container. Use `docker compose ps`
and `docker compose logs --tail=100 api worker initialize` to inspect status.

App images run as UID 10001 with capabilities dropped, no-new-privileges and
read-only root filesystems. Temporary directories are tmpfs. Persistence belongs
to service volumes. API/Web bind only host loopback. Redis uses a password and
no-eviction memory policy; OpenSearch uses an app role restricted to AEGIS indices.

## Production configuration

Use an HTTPS ingress with request limits/timeouts and appropriate SSE support.
Set ENVIRONMENT=production, COOKIE_SECURE=true and PUBLIC_ORIGIN to the exact
HTTPS URL. Configure verified TLS for PostgreSQL, Redis and OpenSearch, a separate
runtime DB role, externally managed secrets, encrypted volumes/backups, monitored
disk thresholds and egress allowlists. Remove bootstrap/admin provisioning secrets
from long-running runtime environments. Rotate the generated bootstrap password.

One search shard/day and zero replicas suit single-node local deployment. Multi-node
production needs replicas, index lifecycle planning and measured shard sizing.
Daily event indices are `aegis-events-YYYY.MM.DD`; the alias is `aegis-events`.
No index per event is created. Explicit daily indices provide the rollover boundary.

API replicas are stateless; sessions live in PostgreSQL and shared counters in
Redis. Workers coordinate through PostgreSQL organization/queue row locks.
Throughput within a tenant is serialized for correlation ordering. Partitioning
large tenants by correlation identity needs deliberate implementation and testing.

## Retention

RETENTION_DAYS declares the retention eligibility threshold but **does not delete
data automatically**. Source evidence and linked case/alert/report evidence should
be kept under an approved policy. Snapshot indices and back up PostgreSQL before
administratively deleting expired, unreferenced evidence. Hot/warm tier movement
and automated legal holds are not installed. Monitor disk capacity.

## Backups

PostgreSQL custom-format backup inside the container:

```sh
docker compose exec postgres pg_dump -U aegis -d aegis -Fc -f /tmp/aegis.dump
docker compose cp postgres:/tmp/aegis.dump ./aegis.dump
```

Protect/encrypt the copied file. Restore to a **new isolated database**, not an
active production database:

```sh
docker compose cp ./aegis.dump postgres:/tmp/restore.dump
docker compose exec postgres createdb -U aegis aegis_restore
docker compose exec postgres pg_restore -U aegis -d aegis_restore --no-owner /tmp/restore.dump
```

Point an isolated API at the restore, verify migrations/audit chains and compare
event evidence hashes. Backup AUDIT_SECRET separately: losing it prevents chain
verification. Schema-owner privileges are required for restoring audit triggers.

OpenSearch: configure an approved snapshot repository (filesystem or cloud plugin)
and snapshot `aegis-events-*` plus relevant templates/security configuration.
The local image does not provision a remote snapshot bucket. PostgreSQL evidence
can rebuild the search projection through a controlled reindex job. Redis windows
are short-lived; restoring Redis is not a substitute for replaying detection state.

Recovery ordering: database/config secrets → migrations → search/template → Redis
→ API/workers → verify acceptance → enable collectors. Avoid running a worker on
an incomplete restore. Define measured RPO/RTO through scheduled restore drills;
this repository does not invent recovery-time guarantees.
