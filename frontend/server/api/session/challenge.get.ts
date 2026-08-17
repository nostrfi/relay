import type { ChallengeResponse } from '~~/shared/types/session'

/** Attempts per address before the challenge endpoint refuses. */
const CHALLENGE_RATE_LIMIT = { limit: 30, windowMs: 60_000 }

export default defineEventHandler(async (event): Promise<ChallengeResponse> => {
  const address = getRequestIP(event, { xForwardedFor: true }) ?? 'unknown'
  if (!allowRequest(`challenge:${address}`, CHALLENGE_RATE_LIMIT)) {
    throw createError({ statusCode: 429, statusMessage: 'Too many requests' })
  }

  return { challenge: issueChallenge() }
})
