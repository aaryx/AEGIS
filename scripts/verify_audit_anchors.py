"""CLI Command for Independent Audit Checkpoint Anchor Verification.

Verifies local database AuditCheckpoints against external immutable WORM/S3 anchors.
Detects missing checkpoints, corrupted hashes, forged signatures, or unauthorized
local modifications by rogue database administrators.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from sqlalchemy import select

from aegis.audit_anchor import get_audit_anchor_adapter, verify_external_anchors
from aegis.config import get_settings
from aegis.db import Organization, database


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify AEGIS Audit Checkpoints Against External Immutable Anchors"
    )
    parser.add_argument(
        "--org",
        type=str,
        default=None,
        help="Organization ID to verify (default: verify all organizations)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format",
    )
    args = parser.parse_args()

    settings = get_settings()
    engine, session_factory = database(settings.database_url)
    adapter = get_audit_anchor_adapter(settings)

    if not adapter:
        error_payload = {
            "error": "No external audit anchor adapter is configured in settings",
            "backend": settings.audit_anchor_backend,
            "status": "NOT_CONFIGURED",
        }
        if args.json:
            print(json.dumps(error_payload, indent=2))
        else:
            print("[!] ERROR: No external audit anchor adapter configured.")
            print(f"[*] Audit anchor backend: {settings.audit_anchor_backend}")
            print("[*] To configure, set AUDIT_ANCHOR_BACKEND=s3 or local_worm in environment.")
        engine.dispose()
        return 1

    reports: list[dict[str, Any]] = []
    overall_valid = True

    try:
        with session_factory() as db:
            if args.org:
                org_ids = [args.org]
            else:
                org_ids = list(db.scalars(select(Organization.id)))

            for org_id in org_ids:
                report = verify_external_anchors(db, settings, org_id, adapter)
                report_dict = report.to_dict()
                reports.append(report_dict)

                if report.status != "VALID":
                    overall_valid = False

        if args.json:
            print(json.dumps({"reports": reports, "overall_valid": overall_valid}, indent=2))
        else:
            print("=" * 70)
            print(" AEGIS IMMUTABLE AUDIT CHECKPOINT VERIFICATION REPORT")
            print("=" * 70)
            print(f"[*] Anchor Adapter: {adapter.__class__.__name__}")
            for r in reports:
                status_color = "PASS" if r["status"] == "VALID" else "FAIL"
                print(f"\n[Organization: {r['organization_id']}] -> Status: [{status_color}] ({r['status']})")
                print(f"  - Total Local Checkpoints:  {r['total_local_checkpoints']}")
                print(f"  - Verified External Anchors: {r['verified_count']}")
                print(f"  - Missing External Anchors:  {r['missing_count']}")
                print(f"  - Tampered / Mismatched:     {r['tampered_count']}")
                if r["errors"]:
                    print("  - Discrepancy Details:")
                    for err in r["errors"]:
                        print(f"    * {err}")
            print("\n" + "=" * 70)
            if overall_valid:
                print("[+] All audit checkpoints and external immutable anchors are 100% VALID.")
            else:
                print("[-] WARNING: One or more audit checkpoints FAILED verification.")
            print("=" * 70)

        return 0 if overall_valid else 2
    finally:
        engine.dispose()


if __name__ == "__main__":
    sys.exit(main())
