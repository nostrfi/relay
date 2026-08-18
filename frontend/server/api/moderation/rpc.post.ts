/**
 * Forwards a NIP-86 management call to the relay.
 *
 * The browser signs it; this route only proxies. It must not re-serialize
 * the body — NIP-98's payload tag is a hash of the exact bytes, so any
 * reformatting here would make the relay refuse a valid signature.
 */
export default defineEventHandler(async (event) => {
  await requireAdminSession(event)

  const authorization = getRequestHeader(event, 'authorization')
  if (!authorization) {
    throw createError({ statusCode: 400, statusMessage: 'Missing relay authorization header' })
  }

  const body = await readRawBody(event, 'utf8')
  if (!body) {
    throw createError({ statusCode: 400, statusMessage: 'Missing request body' })
  }

  const { relayApiBase } = useRuntimeConfig(event)

  // Plain fetch, not $fetch: the relay answers method-level failures with a
  // 200 and an {"error"} envelope but auth failures with a 401, and both
  // bodies matter to the caller. $fetch would throw the 401 body away.
  const response = await fetch(relayApiBase, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/nostr+json+rpc',
      'Authorization': authorization
    },
    body
  })

  const text = await response.text()
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    throw createError({
      statusCode: 502,
      statusMessage: `Relay returned a non-JSON response (${response.status})`
    })
  }

  // The relay separates the two failure kinds by status: a method-level
  // problem ("pubkey must be 64 hex characters") is a 200 carrying an error
  // envelope, while a failed operator check is a 401. Preserving that lets
  // the caller tell an actionable validation message from a refusal it
  // cannot interpret — flattening both into a 200 lost the distinction.
  if (!response.ok) {
    throw createError({
      statusCode: response.status,
      statusMessage: (parsed as { error?: string })?.error ?? 'The relay refused the request'
    })
  }

  return parsed
})
