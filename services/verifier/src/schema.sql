-- Mandate Clearing: Verifier persistence layer
-- Run once against Postgres to initialize.

CREATE TABLE IF NOT EXISTS nonces (
  attestation_hash TEXT PRIMARY KEY,
  mandate_id       TEXT NOT NULL,
  seen_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ledger (
  mandate_id TEXT PRIMARY KEY,
  spent      BIGINT NOT NULL DEFAULT 0,
  orders     INT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS verdicts (
  id                SERIAL PRIMARY KEY,
  mandate_hash      TEXT NOT NULL,
  order_hash        TEXT NOT NULL,
  attestation_hash  TEXT NOT NULL,
  trace_hash        TEXT,
  decision          TEXT NOT NULL CHECK (decision IN ('APPROVE', 'REJECT')),
  liability         TEXT NOT NULL CHECK (liability IN ('PRINCIPAL', 'AGENT_PROVIDER', 'NONE')),
  violations        JSONB NOT NULL DEFAULT '[]',
  remaining_budget  BIGINT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_verdicts_mandate ON verdicts (mandate_hash);
CREATE INDEX IF NOT EXISTS idx_verdicts_attestation ON verdicts (attestation_hash);
CREATE INDEX IF NOT EXISTS idx_verdicts_created ON verdicts (created_at);
