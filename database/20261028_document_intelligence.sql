-- Round 14: document intelligence engine — fingerprint registry and
-- tamper-evident verification chain (canonical PostgreSQL migration;
-- doc-verification service formerly fell back to SQLite; removed Round 27).
BEGIN;

CREATE TABLE IF NOT EXISTS doc_registry (
    doc_hash       CHAR(64) PRIMARY KEY,
    tenant_id      VARCHAR(64) NOT NULL,
    doc_type       VARCHAR(64),
    dhash          TEXT,
    phash          TEXT,
    status         VARCHAR(16) NOT NULL DEFAULT 'active',
    revoke_reason  VARCHAR(512),
    registered_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS doc_registry_tenant_idx ON doc_registry (tenant_id);
CREATE INDEX IF NOT EXISTS doc_registry_status_idx ON doc_registry (status);

CREATE TABLE IF NOT EXISTS doc_verification_chain (
    id           BIGSERIAL PRIMARY KEY,
    tenant_id    VARCHAR(64) NOT NULL,
    doc_hash     CHAR(64) NOT NULL,
    event_type   VARCHAR(64) NOT NULL,
    payload_hash CHAR(64) NOT NULL,
    prev_hash    TEXT NOT NULL,
    entry_hash   CHAR(64) NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS doc_verification_chain_doc_idx
    ON doc_verification_chain (tenant_id, doc_hash, id);

COMMIT;
