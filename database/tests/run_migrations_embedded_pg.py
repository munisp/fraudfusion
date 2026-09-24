#!/usr/bin/env python3
"""Fresh-DB migration-chain verification on a real embedded PostgreSQL.

Uses pgserver (pip install pgserver) — no docker, no system postgres needed.
Applies every database/*.sql file in lexical order TWICE (idempotency), then
runs the SQL verification tests and the multi-tenant ledger stress test.

Usage:
    pip install pgserver
    XDG_RUNTIME_DIR=/tmp/xdg python3 database/tests/run_migrations_embedded_pg.py

Exit code 0 = all migrations applied, idempotent, and all tests passed.
"""
import glob
import os
import subprocess
import sys

import pgserver

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PGDATA = os.environ.get("PG_TEST_DATA", "/tmp/fraudfusion-pgtest")


def main() -> int:
    srv = pgserver.get_server(PGDATA)
    uri = srv.get_uri()
    psql = os.path.join(os.path.dirname(pgserver.__file__), "pginstall", "bin", "psql")

    files = sorted(glob.glob(os.path.join(REPO, "database", "*.sql")))
    failures = []

    def apply(f: str) -> str | None:
        """Apply one SQL file via the psql binary with ON_ERROR_STOP.

        NOTE: pgserver.psql() does NOT raise on SQL errors (it just prints
        them), which can mask failures — always use psql -v ON_ERROR_STOP=1
        and check the return code.
        """
        r = subprocess.run([psql, uri, "-v", "ON_ERROR_STOP=1", "-q", "-f", f],
                           capture_output=True, text=True, timeout=300)
        if r.returncode != 0 or "ERROR" in r.stderr:
            return (r.stderr or r.stdout)[:300]
        return None

    for f in files:
        err = apply(f)
        if err:
            failures.append(os.path.basename(f))
            print("FAIL", os.path.basename(f), "->", err)
        else:
            print("OK  ", os.path.basename(f))
    for f in files:  # second pass: idempotency
        err = apply(f)
        if err:
            failures.append(os.path.basename(f) + " (idempotency)")
            print("IDEM-FAIL", os.path.basename(f), err)
    print(f"migrations: {len(files) - len(failures)}/{len(files)} applied, idempotent")

    for t in sorted(glob.glob(os.path.join(REPO, "database", "tests", "*verification*.sql"))):
        err = apply(t)
        if err:
            failures.append(os.path.basename(t))
            print("FAIL", os.path.basename(t), "->", err)
        else:
            print("PASS", os.path.basename(t))

    # multi-tenant ledger stress: seed accounts, then run balanced journals
    env = dict(os.environ, PGOPTIONS="-c app.stress_tenants=3")
    seed = """DO $$
DECLARE tenant_number integer; tenant text;
BEGIN
  FOR tenant_number IN 1..current_setting('app.stress_tenants')::integer LOOP
    tenant := 'stress-tenant-' || tenant_number;
    INSERT INTO ledger_accounts (id, tenant_id, account_code, account_type, currency)
    VALUES (md5(tenant || ':debit')::uuid, tenant, 'stress-debit', 'asset', 'USD'),
           (md5(tenant || ':credit')::uuid, tenant, 'stress-credit', 'liability', 'USD')
    ON CONFLICT (tenant_id, account_code, currency) DO NOTHING;
  END LOOP;
END $$;"""
    r = subprocess.run([psql, uri, "-v", "ON_ERROR_STOP=1", "-c", seed],
                       capture_output=True, text=True, env=env, timeout=120)
    if r.returncode != 0:
        failures.append("stress-seed")
        print("FAIL stress-seed", r.stderr[:250])
    stress = os.path.join(REPO, "database", "tests", "20260822_ledger_stress_transaction.sql")
    bad = 0
    for t in range(1, 4):
        for seq in range(1, 26):
            r = subprocess.run(
                [psql, uri, "-v", "ON_ERROR_STOP=1", "-v", f"tenant=stress-tenant-{t}",
                 "-v", f"sequence={seq}", "-f", stress],
                capture_output=True, text=True, env=env, timeout=120)
            if r.returncode != 0:
                bad += 1
    print(f"ledger stress: {75 - bad}/75 balanced journals posted")
    if bad:
        failures.append("ledger-stress")

    if failures:
        print("FAILURES:", failures)
        return 1
    print("ALL GREEN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
