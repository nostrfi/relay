import { describe, expect, it } from 'vitest'
import { loginUrlFor } from '../shared/utils/login-url'

const ORIGIN = 'https://relay.example.com'

describe('loginUrlFor', () => {
  it('joins the configured base path without losing the separator', () => {
    // Regression: string concatenation produced '/adminapi/session/login',
    // which the server's path comparison refused with 401.
    expect(loginUrlFor('/admin', ORIGIN)).toBe(`${ORIGIN}/admin/api/session/login`)
  })

  it('tolerates a trailing slash on the base path', () => {
    expect(loginUrlFor('/admin/', ORIGIN)).toBe(`${ORIGIN}/admin/api/session/login`)
  })

  it('handles a root base path', () => {
    expect(loginUrlFor('/', ORIGIN)).toBe(`${ORIGIN}/api/session/login`)
  })

  it('matches the path the server compares against', () => {
    // The server checks getRequestURL(event).pathname, which carries the base.
    expect(new URL(loginUrlFor('/admin', ORIGIN)).pathname).toBe('/admin/api/session/login')
  })
})
