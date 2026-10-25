-- Fraud Signals shadow mode (Round 20): shadow evaluations are audited with
-- mode='shadow' so live traffic can be scored without enforcement, and score
-- distributions can be replayed for threshold tuning.

ALTER TABLE signal_evals ADD COLUMN IF NOT EXISTS mode TEXT NOT NULL DEFAULT 'enforce';
