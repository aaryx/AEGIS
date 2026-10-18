# OpenSearch In-Transit Transport Security & TLS Guide

This operational guide details the cryptographic architecture, certificate provisioning, Compose deployment, and zero-downtime rotation procedures for OpenSearch in AEGIS production environments.

---

## 1. Cryptographic Architecture

In production deployments, OpenSearch handles sensitive security telemetry, including hostnames, IP addresses, usernames, and forensic event logs. Unencrypted HTTP transport across Docker bridge networks or Kubernetes pods exposes telemetry to eavesdropping, packet manipulation, and credential interception.

AEGIS implements end-to-end transport encryption across two distinct layers:
1. **HTTP REST Transport Layer (`plugins.security.ssl.http`):** Encrypts all client-to-cluster traffic between the AEGIS API/worker services and OpenSearch. Strict certificate validation (`verify_certs=True`) is enforced with a pinned root/intermediate CA bundle (`opensearch_ca`).
2. **Node-to-Node Cluster Transport Layer (`plugins.security.ssl.transport`):** Encrypts inter-node cluster gossip, shard replication, and internal cluster coordination on port 9300. Enforces mutual TLS (mTLS) with hostname verification.

---

## 2. Certificate Generation Procedure

All certificates must be signed by an internal organizational Certificate Authority (CA) or a dedicated PKI.

> [!CAUTION]
> Never commit private keys (`*.key`, `*.pem`) or certificates to Git repositories. Keys must be stored in secure secrets managers (e.g., HashiCorp Vault, AWS Secrets Manager, Kubernetes Secrets).

### Step 1: Generate Internal Root CA
```bash
# Generate Root CA private key (4096-bit RSA or Ed25519)
openssl genrsa -out root-ca.key 4096

# Generate Self-Signed Root Certificate (valid for 5 years)
openssl req -new -x509 -sha256 -key root-ca.key -out root-ca.pem -days 1825 \
  -subj "/C=US/ST=Security/L=Defense/O=AEGIS/OU=Infrastructure/CN=AEGIS-Root-CA"
```

### Step 2: Generate Node Certificate with Subject Alternative Names (SAN)
Create an OpenSSL SAN configuration file (`node.cnf`):
```ini
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = Security
L = Defense
O = AEGIS
OU = DataLayer
CN = opensearch

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = opensearch
DNS.2 = localhost
IP.1 = 127.0.0.1
```

Generate the key, Certificate Signing Request (CSR), and signed certificate:
```bash
# Generate node private key
openssl genrsa -out opensearch-node-raw.key 2048

# OpenSearch Java security plugin requires PKCS#8 format for private keys
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt \
  -in opensearch-node-raw.key -out opensearch-node-key.pem

# Generate CSR
openssl req -new -key opensearch-node-key.pem -out opensearch-node.csr -config node.cnf

# Sign node certificate using Root CA
openssl x509 -req -in opensearch-node.csr -CA root-ca.pem -CAkey root-ca.key \
  -CAcreateserial -out opensearch-node.pem -days 365 -sha256 -extfile node.cnf -extensions v3_req
```

---

## 3. Production Deployment Configuration

Use the production Compose overlay [`compose.production.yaml`](file:///d:/Project/Aegis/compose.production.yaml):

```bash
docker compose -f compose.yaml -f compose.production.yaml up -d
```

### Key Configuration Directives:
```yaml
services:
  opensearch:
    environment:
      plugins.security.ssl.http.enabled: "true"
      plugins.security.ssl.http.pemcert_filepath: certs/opensearch-node.pem
      plugins.security.ssl.http.pemkey_filepath: certs/opensearch-node-key.pem
      plugins.security.ssl.http.pemtrustedcas_filepath: certs/root-ca.pem
      plugins.security.ssl.transport.enabled: "true"
      plugins.security.ssl.transport.pemcert_filepath: certs/opensearch-node.pem
      plugins.security.ssl.transport.pemkey_filepath: certs/opensearch-node-key.pem
      plugins.security.ssl.transport.pemtrustedcas_filepath: certs/root-ca.pem
      plugins.security.ssl.transport.enforce_hostname_verification: "true"
    volumes:
      - ./certs/opensearch:/usr/share/opensearch/config/certs:ro
```

### Application Client Settings (`.env`):
```bash
ENVIRONMENT=production
OPENSEARCH_URL=https://opensearch:9200
OPENSEARCH_CA=/usr/share/opensearch/config/certs/root-ca.pem
COOKIE_SECURE=true
```

---

## 4. Zero-Downtime Certificate Rotation Procedure

Node certificates expire annually; the following procedure ensures uninterrupted event ingestion and search operations:

1. **Pre-Deployment Validation:**  
   Issue the new certificate signed by the active Root CA. Verify certificate validity and SAN extensions before deployment:
   ```bash
   openssl verify -CAfile root-ca.pem opensearch-node-new.pem
   openssl x509 -in opensearch-node-new.pem -noout -text | grep -A 3 "Subject Alternative Name"
   ```

2. **Stage New Certificates:**  
   Place the new `opensearch-node-new.pem` and `opensearch-node-key-new.pem` in `./certs/opensearch/`.

3. **Atomic Swap & Rolling Reload:**  
   - Update symlinks or file paths to point to the new key and certificate.
   - For multi-node clusters: Perform a rolling restart, one node at a time, allowing shards to achieve GREEN cluster status after each node restart:
     ```bash
     curl -fsS --cacert root-ca.pem --user "admin:$OPENSEARCH_ADMIN_PASSWORD" \
       https://localhost:9200/_cluster/health
     ```

4. **CA Certificate Renewal:**  
   When rotating the Root CA:
   - Concatenate old and new CA certificates into a dual-trust bundle (`combined-ca.pem`).
   - Deploy `combined-ca.pem` to all AEGIS API and worker services.
   - Deploy node certificates signed by the new CA.
   - Remove the retired old CA certificate from the bundle.
