#!/usr/bin/env python3
"""hubble_contracts.py — pull the COMPLETE Soroban contract list from the SDF
Hubble public BigQuery dataset (crypto-stellar). This is source (a): the full
enumeration the free stellar.expert API caps at 20 and getEvents can't give
(SAC-dominated). Read-only.

Needs Google credentials ONE TIME (your account):
  Option A (gcloud):   gcloud auth application-default login
                       export GOOGLE_CLOUD_PROJECT=<your-project-id>
  Option B (SA key):   export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
                       export GOOGLE_CLOUD_PROJECT=<your-project-id>

Then: python3 recon/hubble_contracts.py
Output: recon/out/hubble_contracts.json = [{contract_id, wasm_hash}]
Free tier: 1 TB scanned/month. This query scans little (distinct on one table).
"""
import json, os, sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out")
os.makedirs(OUT, exist_ok=True)

try:
    from google.cloud import bigquery
except Exception:
    print("google-cloud-bigquery not installed: pip install --user google-cloud-bigquery")
    sys.exit(1)

if not (os.environ.get("GOOGLE_APPLICATION_CREDENTIALS") or os.path.exists(
    os.path.expanduser("~/.config/gcloud/application_default_credentials.json"))):
    print(__doc__)
    print(">>> No Google credentials found. Do one of the auth options above, then re-run.")
    sys.exit(2)

project = os.environ.get("GOOGLE_CLOUD_PROJECT")
client = bigquery.Client(project=project)
DS = "crypto-stellar.crypto_stellar"


def run(sql):
    return list(client.query(sql).result())


# 1) discover the contract tables/columns (schema-robust)
print("== discovering Hubble contract tables ==")
try:
    tabs = run(f"""
      SELECT table_name FROM `{DS}`.INFORMATION_SCHEMA.TABLES
      WHERE LOWER(table_name) LIKE '%contract%' ORDER BY table_name
    """)
    names = [t.table_name for t in tabs]
    print("contract tables:", names)
except Exception as e:
    print("discovery failed:", repr(e)[:200]); sys.exit(3)

# 2) best-effort: distinct contract instances -> wasm hash.
# contract_data holds ledger entries per contract; the instance entry carries the
# code (wasm) hash. Column names vary by Hubble version, so try candidates.
candidates = [
    f"SELECT DISTINCT contract_id, contract_code_hash AS wasm FROM `{DS}`.contract_data WHERE contract_id IS NOT NULL",
    f"SELECT DISTINCT contract_id, ledger_key_hash AS wasm FROM `{DS}`.contract_data WHERE contract_id IS NOT NULL",
    f"SELECT DISTINCT contract_id FROM `{DS}`.contract_data WHERE contract_id IS NOT NULL",
]
rows = None
for sql in candidates:
    try:
        rows = run(sql + " LIMIT 100000")
        print(f"query OK ({len(rows)} rows): {sql[:90]}...")
        break
    except Exception as e:
        print("try failed:", repr(e)[:120])

if not rows:
    print("no query worked — inspect the schemas above and adjust.")
    sys.exit(4)

out = []
for r in rows:
    d = dict(r.items())
    out.append({"contract_id": d.get("contract_id"), "wasm_hash": d.get("wasm")})
json.dump(out, open(os.path.join(OUT, "hubble_contracts.json"), "w"), indent=1)
uw = len({o["wasm_hash"] for o in out if o.get("wasm_hash")})
print(f"\nHUBBLE: contracts={len(out)} unique_wasm={uw} -> recon/out/hubble_contracts.json")
