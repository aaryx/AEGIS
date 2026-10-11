# AEGIS Incident Response & SOAR Playbook Runbook

## 1. Incident Lifecycle & Progression

Incident stages follow strict NIST SP 800-61 / SANS lifecycle stages. Progression must advance linearly:

`OPEN → TRIAGED → INVESTIGATING → CONTAINMENT → ERADICATION → RECOVERY → RESOLVED → CLOSED`

- Advancing backwards or skipping stages is rejected with `409 Conflict`.
- Transitioning to `RESOLVED` or `CLOSED` requires mandatory resolution notes.
- Optimistic concurrency control is enforced via `revision` counter; stale writes fail with `409 Conflict`.
- Assignees must belong to the authenticated organization.

---

## 2. Two-Person Controlled SOAR Playbook Execution

High-impact actions (`isolate_host`, `unisolate_host`, `terminate_process`, `disable_account`, `block_ioc`) cannot be executed by an individual analyst alone.

```mermaid
sequenceDiagram
    autonumber
    actor Requester as Senior Analyst
    actor Approver as SOC Manager
    participant API as AEGIS API (aegis/response.py)
    participant DB as PostgreSQL
    participant Agent as Endpoint Agent (aegis/agent.py)

    Requester->>API: POST /playbooks/request (Idempotency-Key, target, action)
    API->>DB: Record PlaybookExecution (status=APPROVAL_REQUIRED)
    API-->>Requester: 200 OK (id=EXEC-01, status=APPROVAL_REQUIRED)

    Approver->>API: POST /playbooks/EXEC-01/approve (Human session)
    Note over API: Rejects if Approver == Requester
    API->>DB: Update PlaybookExecution (status=APPROVED, approved_by=Approver)
    API-->>Approver: 200 OK (status=APPROVED)

    Requester->>API: POST /playbooks/EXEC-01/execute
    Note over API: Verifies approval expiration (< response_approval_seconds)
    alt Active Endpoint Agent Available
        API->>DB: Update PlaybookExecution (status=DISPATCHED)
        API-->>Requester: 200 OK (status=DISPATCHED, pending_receipt=true)
        Agent->>API: GET /agents/{name}/commands
        API-->>Agent: [ {id: EXEC-01, action: isolate_host, ...} ]
        Agent->>Agent: Apply firewall isolation (netsh / iptables)
        Agent->>Agent: Compute canonical SHA-256 receipt hash
        Agent->>API: POST /agents/{name}/receipts (receipt_hash, status, details)
        Note over API: Cryptographically verifies receipt hash matches payload
        API->>DB: Update PlaybookExecution (status=VERIFIED, enforced_externally=true)
    else Local Policy Only
        API->>DB: Record Entity local policy (status=VERIFIED, enforced_externally=false)
        API-->>Requester: 200 OK (status=VERIFIED)
    end
```

---

## 3. Host Isolation Emergency Rollback

If a machine is accidentally isolated or network containment needs to be lifted:

1. Request an un-isolation playbook:
   ```bash
   curl -X POST "http://localhost:8000/api/v1/playbooks/request" \
     -H "Authorization: Bearer <SENIOR_ANALYST_TOKEN>" \
     -H "Idempotency-Key: emergency-uniso-$(date +%s)" \
     -H "Content-Type: application/json" \
     -d '{"action": "unisolate_host", "target": "<ENTITY_ID_OR_HOSTNAME>"}'
   ```
2. Independent SOC Manager approves:
   ```bash
   curl -X POST "http://localhost:8000/api/v1/playbooks/<EXECUTION_ID>/approve" \
     -H "Authorization: Bearer <SOC_MANAGER_TOKEN>"
   ```
3. Dispatch execution:
   ```bash
   curl -X POST "http://localhost:8000/api/v1/playbooks/<EXECUTION_ID>/execute" \
     -H "Authorization: Bearer <SENIOR_ANALYST_TOKEN>"
   ```
4. On the endpoint, the agent automatically polls the command and deletes firewall rules (`netsh advfirewall firewall delete rule` on Windows, or `iptables -F` on Linux).
