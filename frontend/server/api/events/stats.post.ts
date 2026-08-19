/**
 * Forwards a signed statistics request to the relay.
 *
 * Identical in shape to the browse proxy next door: the browser signs, this
 * route forwards the bytes unread, and the relay authorizes. The counts are
 * as privileged as the events they count.
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
  const relayUrl = `${relayApiBase.replace(/\/$/, '')}/api/events/stats`

  const response = await fetch(relayUrl, {
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

  // Which relay answered, so a chart showing nothing can be traced to a hop
  // rather than guessed at — the lesson of nostrfi/workspace#49.
  console.info(`event stats proxied: relay=${relayUrl} status=${response.status} bytes=${text.length}`)

  if (!response.ok) {
    throw createError({
      statusCode: response.status,
      statusMessage: (parsed as { error?: string })?.error ?? 'The relay refused the request',
      data: {
        relayReason: (parsed as { reason?: string })?.reason,
        ...await collectRefusalDiagnostics(relayApiBase, response, '/api/events/stats')
      }
    })
  }

  return parsed
})
