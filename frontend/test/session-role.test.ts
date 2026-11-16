import { describe, expect, it } from 'vitest'
import {
  isWhoamiBody,
  ROLE_RECHECK_SECONDS,
  roleEvidenceFrom,
  roleFromWhoami,
  roleRecheckDue,
  roleSatisfies,
  sessionEndedFor,
  signerPubkeyOf,
  WHOAMI_REQUEST
} from '../shared/utils/session-role'

const OWNER = 'a'.repeat(64)
const ADMIN = 'b'.repeat(64)

describe('roleSatisfies', () => {
  it('mirrors the relay: the owner can do what an admin can, not the reverse', () => {
    expect(roleSatisfies('owner', 'admin')).toBe(true)
    expect(roleSatisfies('owner', 'owner')).toBe(true)
    expect(roleSatisfies('admin', 'admin')).toBe(true)
    expect(roleSatisfies('admin', 'owner')).toBe(false)
  })

  it('admits no one without a role', () => {
    expect(roleSatisfies(undefined, 'admin')).toBe(false)
  })
})

describe('roleRecheckDue', () => {
  const now = 1_800_000_000

  it('is not due inside the interval', () => {
    expect(roleRecheckDue(now - ROLE_RECHECK_SECONDS + 1, now)).toBe(false)
  })

  it('is due once the interval has passed', () => {
    expect(roleRecheckDue(now - ROLE_RECHECK_SECONDS, now)).toBe(true)
  })

  it('is due when the role was never confirmed', () => {
    expect(roleRecheckDue(undefined, now)).toBe(true)
  })
})

describe('roleFromWhoami', () => {
  it('reads the role the relay names for the expected key', () => {
    expect(roleFromWhoami({ result: { pubkey: OWNER, role: 'owner' } }, OWNER)).toBe('owner')
    expect(roleFromWhoami({ result: { pubkey: ADMIN, role: 'admin' } }, ADMIN)).toBe('admin')
  })

  it('refuses an answer about a different key than the one that signed in', () => {
    // A captured admin whoami paired with a challenge signed by anyone else.
    expect(roleFromWhoami({ result: { pubkey: ADMIN, role: 'admin' } }, OWNER)).toBeNull()
  })

  it('refuses roles the dashboard does not know, errors, and junk', () => {
    expect(roleFromWhoami({ result: { pubkey: OWNER, role: 'moderator' } }, OWNER)).toBeNull()
    expect(roleFromWhoami({ error: 'unsupported method' }, OWNER)).toBeNull()
    expect(roleFromWhoami(null, OWNER)).toBeNull()
    expect(roleFromWhoami('owner', OWNER)).toBeNull()
  })
})

describe('isWhoamiBody', () => {
  it('accepts the body the browser signs', () => {
    expect(isWhoamiBody(JSON.stringify(WHOAMI_REQUEST))).toBe(true)
    expect(isWhoamiBody('{"method":"whoami"}')).toBe(true)
  })

  it('refuses every other method, so sign-in cannot forward anything else', () => {
    expect(isWhoamiBody('{"method":"banpubkey","params":["x"]}')).toBe(false)
    expect(isWhoamiBody('{"method":"whoami","params":["x"]}')).toBe(false)
    expect(isWhoamiBody('not json')).toBe(false)
    expect(isWhoamiBody('')).toBe(false)
  })
})

describe('signerPubkeyOf', () => {
  const header = (event: unknown) => `Nostr ${Buffer.from(JSON.stringify(event)).toString('base64')}`

  it('reads the pubkey from a NIP-98 header', () => {
    expect(signerPubkeyOf(header({ pubkey: ADMIN, kind: 27235 }))).toBe(ADMIN)
  })

  it('is null for anything that is not one', () => {
    expect(signerPubkeyOf(undefined)).toBeNull()
    expect(signerPubkeyOf('Bearer abc')).toBeNull()
    expect(signerPubkeyOf('Nostr !!!')).toBeNull()
    expect(signerPubkeyOf(header({ pubkey: 'not-hex' }))).toBeNull()
  })
})

describe('roleEvidenceFrom', () => {
  it('reads an accepted request as a confirmed role', () => {
    expect(roleEvidenceFrom(200, undefined)).toBe('confirmed')
  })

  it('reads a bare 401 as a revoked key: the relay explains everything else', () => {
    expect(roleEvidenceFrom(401, undefined)).toBe('revoked')
    expect(roleEvidenceFrom(401, '')).toBe('revoked')
  })

  it('does not end a session over a verification failure, a role refusal, or an outage', () => {
    expect(roleEvidenceFrom(401, 'event created_at is more than 60 seconds from now')).toBe('unknown')
    expect(roleEvidenceFrom(403, 'owner only')).toBe('unknown')
    expect(roleEvidenceFrom(502, undefined)).toBe('unknown')
  })
})

describe('sessionEndedFor', () => {
  // Shaped like a $fetch error for createError({ data: { sessionEnded: true } }).
  const ended = { data: { data: { sessionEnded: true } } }

  it('signs out when the ended session is the one signed in', () => {
    expect(sessionEndedFor(ended, ADMIN, ADMIN)).toBe(true)
  })

  it('leaves a session that replaced the one the request was signed for', () => {
    expect(sessionEndedFor(ended, ADMIN, OWNER)).toBe(false)
  })

  it('does nothing once nobody is signed in', () => {
    expect(sessionEndedFor(ended, ADMIN, undefined)).toBe(false)
  })

  it('does nothing without a signing key', () => {
    expect(sessionEndedFor(ended, undefined, undefined)).toBe(false)
  })

  it('ignores failures that did not end the session', () => {
    expect(sessionEndedFor({ data: { data: {} } }, ADMIN, ADMIN)).toBe(false)
    expect(sessionEndedFor(new Error('network'), ADMIN, ADMIN)).toBe(false)
    expect(sessionEndedFor(null, ADMIN, ADMIN)).toBe(false)
  })
})
