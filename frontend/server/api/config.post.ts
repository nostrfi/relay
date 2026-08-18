/**
 * Forwards a signed configuration read to the relay.
 *
 * As with the moderation proxy, the browser signs and this route only
 * forwards: it must not re-serialize the body, because NIP-98's payload tag
 * hashes the exact bytes.
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

  const response = await fetch(`${relayApiBase.replace(/\/$/, '')}/api/config`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
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

  if (!response.ok) {
    throw createError({
      statusCode: response.status,
      statusMessage: (parsed as { error?: string })?.error ?? 'The relay refused the request'
    })
  }

  return parsed
})
