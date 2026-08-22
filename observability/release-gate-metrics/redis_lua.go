package main

const redisClaimAndRateLimitLua = `
-- KEYS[1] = replay key, KEYS[2] = key-ID-scoped rate-window key
-- ARGV[1] = event identity, ARGV[2] = current Unix time in milliseconds
-- ARGV[3] = rate window in milliseconds, ARGV[4] = maximum accepted events
-- ARGV[5] = replay key TTL in milliseconds
local replayKey = KEYS[1]
local rateKey = KEYS[2]
local eventID = ARGV[1]
local nowMS = tonumber(ARGV[2])
local windowMS = tonumber(ARGV[3])
local maxEvents = tonumber(ARGV[4])
local replayTTLMS = tonumber(ARGV[5])

-- Replay detection comes first: a retry must remain idempotent even if the
-- current rate window is otherwise full.
if redis.call("EXISTS", replayKey) == 1 then
  return {1, 0}
end

-- Sliding-window cleanup and cardinality check are executed by Redis as part
-- of this one script, so concurrent replicas cannot race between check and add.
local cutoff = nowMS - windowMS
redis.call("ZREMRANGEBYSCORE", rateKey, "-inf", cutoff)
local current = redis.call("ZCARD", rateKey)
if current >= maxEvents then
  local oldest = redis.call("ZRANGE", rateKey, 0, 0, "WITHSCORES")
  local retryAfterMS = windowMS
  if #oldest >= 2 then
    retryAfterMS = math.max(1, (tonumber(oldest[2]) + windowMS) - nowMS)
  end
  return {2, retryAfterMS}
end

-- Event IDs are already SHA-256 digests. ZADD uses the unique digest as the
-- member, while PSETEX makes the accepted event globally replay-idempotent.
redis.call("ZADD", rateKey, nowMS, eventID)
redis.call("PEXPIRE", rateKey, windowMS)
redis.call("PSETEX", replayKey, replayTTLMS, "1")
return {0, 0}
`
