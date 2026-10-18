# AEGIS IRONCLAD PHASE 7 — STAGING QUALIFICATION RUNBOOK

**Target Environment:** Controlled Staging Environment (Multi-Node / Kubernetes / Isolated Staging Host)  
**Document Purpose:** Provide operations, reliability, and security engineers with a reproducible, non-destructive execution runbook to validate live infrastructure, OpenSearch TLS, PostgreSQL concurrency, and zero-skip release gates before advancing to a Production Pilot.  
**Branch Baseline:** `feature/ironclad-qualification`  

---

## 1. Prerequisites and Environmental Safeguards

### Minimum Hardware Specification
- **CPU:** 4 vCPUs minimum (8 vCPUs recommended for concurrency suite)
- **RAM:** 16 GB physical RAM minimum (OpenSearch requires 2 GB JVM heap; PostgreSQL requires 2 GB shared buffers)
- **Disk:** 50 GB NVMe / SSD free storage

### Security & Isolation Invariants
> [!IMPORTANT]
> **Safety Rule 1:** The commands in this runbook must strictly target dedicated test databases (e.g., `aegis_test`). Never execute these integration tests against production or staging operational databases (`/aegis`).  
> **Safety Rule 2:** Ensure `ENVIRONMENT=staging` or `ENVIRONMENT=testing`. The application will automatically reject integration suites if `ENVIRONMENT=production`.  
> **Safety Rule 3:** Never commit PKI private keys or production `.env` files to source control.

---

## 2. Infrastructure Setup (Docker Compose Production Overlay)

### Step 2.1: Generate Ephemeral PKI Certificates for OpenSearch
Follow [`docs/operations/opensearch_tls_guide.md`](file:///d:/Project/Aegis/docs/operations/opensearch_tls_guide.md) to generate the Certificate Authority and node certificates:

```bash
mkdir -p certs
cd certs

# 1. Create Root Certificate Authority
openssl req -x509 -newkey rsa:4096 -sha256 -nodes -days 365 \
  -keyout root-ca-key.pem -out root-ca.pem \
  -subj "/C=US/ST=Security/L=Infra/O=AEGIS/OU=PKI/CN=AEGIS-Root-CA"

# 2. Create Node CSR with Subject Alternative Names (SAN)
openssl req -newkey rsa:2048 -nodes \
  -keyout opensearch-node-key-pkcs1.pem -out opensearch-node.csr \
  -subj "/C=US/ST=Security/L=Infra/O=AEGIS/OU=SIEM/CN=opensearch" \
  -addext "subjectAltName=DNS:opensearch,DNS:localhost,IP:127.0.0.1"

# 3. Convert Private Key to PKCS#8 format (Required by OpenSearch Security Plugin)
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt \
  -in opensearch-node-key-pkcs1.pem -out opensearch-node-key.pem

# 4. Sign Node Certificate using Root CA
openssl x509 -req -in opensearch-node.csr -CA root-ca.pem -CAkey root-ca-key.pem \
  -CAcreateserial -out opensearch-node.pem -days 365 -sha256 \
  -copy_extensions copyall

# Set strict permissions
chmod 600 *.pem
cd ..
```

### Step 2.2: Launch Infrastructure with Production Overlay
```bash
# Launch PostgreSQL 17, Redis 7, and OpenSearch with TLS enabled
docker compose -f compose.yaml -f compose.production.yaml up -d --wait
```

### Step 2.3: Verify Container Health
```bash
docker compose ps
# Expected: aegis-postgres (healthy), aegis-redis (healthy), aegis-opensearch (healthy)
```

---

## 3. OpenSearch TLS Live Verification Procedures

Before running application integration, perform live TLS socket handshakes to prove that certificate verification is actively enforced and cannot be bypassed.

### Test Case 1: Plaintext HTTP Must Be Rejected
```bash
curl -i http://127.0.0.1:9200
# Expected Response: Client receives SSL handshake failure or immediate connection reset
# (Confirming plaintext HTTP is completely disabled)
```

### Test Case 2: Untrusted / Missing CA Must Fail Fast
```bash
curl -i https://127.0.0.1:9200
# Expected Response:
# curl: (60) SSL certificate problem: self-signed certificate in certificate chain
# Exit Code: 60 (Failure)
```

### Test Case 3: Hostname Mismatch Must Fail
```bash
# Attempt connection to 127.0.0.1 while CA is trusted, but without matching SAN if connecting via arbitrary IP
curl -i --cacert certs/root-ca.pem https://127.0.0.2:9200
# Expected Response:
# curl: (51) SSL: certificate subject name does not match target host name
# Exit Code: 51 (Failure)
```

### Test Case 4: Valid Trusted CA & Matching Hostname Must Succeed
```bash
curl -i --cacert certs/root-ca.pem -u aegis:${OPENSEARCH_PASSWORD} https://127.0.0.1:9200
# Expected Response:
# HTTP/1.1 200 OK
# JSON cluster status payload returned with OpenSearch version 2.19.1
```

---

## 4. Test Database Provisioning & Schema Migration

Execute the automated safety preparation procedure to establish `aegis_test`:

```bash
# Export staging environment configuration
export ENVIRONMENT=testing
export AEGIS_POSTGRES_TEST_DB=aegis_test
export POSTGRES_PASSWORD="<staging_password>"
export REDIS_PASSWORD="<staging_password>"
export OPENSEARCH_PASSWORD="<staging_password>"

# Target dedicated test DB
export AEGIS_POSTGRES_TEST_URL="postgresql+psycopg://aegis:${POSTGRES_PASSWORD}@127.0.0.1:5432/aegis_test"
export DATABASE_URL="${AEGIS_POSTGRES_TEST_URL}"
export REDIS_URL="redis://:${REDIS_PASSWORD}@127.0.0.1:6379/0"
export OPENSEARCH_URL="https://127.0.0.1:9200"
export OPENSEARCH_CA="certs/root-ca.pem"
export AEGIS_INTEGRATION=1

# Execute database preparation via Alembic
alembic -x sqlalchemy.url="${AEGIS_POSTGRES_TEST_URL}" upgrade head
```

---

## 5. Execution of the CI Release Gate

Execute the mandatory integration gate script:

```bash
python scripts/integration_gate.py
```

### Expected Output Criteria:
- Loopback reachability verified for PostgreSQL (5432), Redis (6379), and OpenSearch (9200).
- Database safety validator confirms target is `aegis_test` and `ENVIRONMENT` is `testing`.
- Execution summary:
  ```
  === CI Release Gate Verification Summary ===
  Passed:     17
  Failed:     0
  Errors:     0
  Skipped:    0
  Deselected: 0
  RELEASE GATE PASSED: All mandatory external integration tests verified successfully (0 skips).
  ```
- **Exit Code:** `0`.

---

## 6. Live PostgreSQL Concurrency & Isolation Execution

Execute the full PostgreSQL concurrency and race condition suite against `aegis_test`:

```bash
pytest tests/test_postgres_integration.py -v --tb=short
```

### Key Concurrency Verifications:
1. `test_postgres_cerberus_concurrent_evidence_conflict`: Row-level lock contention on alert evidence.
2. `test_postgres_multiprocess_concurrent_audit_writes`: Parallel worker processes writing HMAC audit records without hash collisions or chain corruption.
3. `test_postgres_concurrent_storyline_correlation`: Concurrently correlated security storylines.
4. `test_postgres_simultaneous_duplicate_event_ingestion_race`: High-throughput simultaneous duplicate submissions deduplicated without race conditions.
5. `test_postgres_multi_tenant_concurrent_audit_isolation`: Cross-tenant cryptographic isolation under concurrent load.
6. `test_postgres_lock_timeout_and_abort_recovery`: Transaction abort recovery under lock timeouts.

**Success Criteria:** 21 passed, 0 skipped, 0 failed.

---

## 7. Disaster Recovery & Snapshot Validation

Execute the automated DR drill against isolated recovery databases:

```bash
pytest tests/test_disaster_recovery_and_backup_qualification.py -v
```

### Verification Steps:
1. Snapshot generation using `pg_dump`.
2. SHA-256 artifact checksum verification.
3. Target database `aegis_test_dr_{uuid}` created.
4. Schema and data restored via `pg_restore`.
5. Event count and cryptographic audit chain verified.
6. Target database cleanly dropped.

---

## 8. Teardown and Hygiene

Once staging qualification completes, clean up ephemeral test resources:

```bash
# 1. Terminate test containers
docker compose -f compose.yaml -f compose.production.yaml down -v

# 2. Securely remove ephemeral test certificates
rm -rf certs/

# 3. Clean local dump artifacts
rm -rf local-data/*.dump local-data/*.json
```
