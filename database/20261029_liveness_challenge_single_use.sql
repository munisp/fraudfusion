-- Round 17: single-use liveness challenges (replay protection).
--
-- Before this table, challenges were stateless HMAC tokens: a captured
-- (challenge_id, phases, expires_at, signature) tuple could be replayed
-- for unlimited verifications inside the 120s TTL. Now:
--   * POST /api/v1/biometric/liveness/challenge INSERTs the issued id.
--   * POST /api/v1/biometric/liveness/verify-frames atomically consumes it
--     (UPDATE ... WHERE consumed_at IS NULL; rowcount 0 -> 409 unknown or
--     already consumed).
-- A captured challenge therefore authorizes exactly one verification.

CREATE TABLE IF NOT EXISTS liveness_challenges (
    challenge_id TEXT PRIMARY KEY,
    actor_sub    TEXT NOT NULL DEFAULT '',
    phases       TEXT NOT NULL,
    expires_at   BIGINT NOT NULL,
    consumed_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS liveness_challenges_exp_idx
    ON liveness_challenges (expires_at);

-- Housekeeping helper: drop challenges expired >24h ago (call from cron or
-- a sweeper; keeping it a plain statement so any scheduler can run it).
--   DELETE FROM liveness_challenges
--    WHERE expires_at < EXTRACT(EPOCH FROM now() - interval '24 hours');
