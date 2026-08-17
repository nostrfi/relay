import type { SessionState } from '~~/shared/types/session'

export default defineEventHandler(async (event): Promise<SessionState> => {
  await endAdminSession(event)
  return { authenticated: false }
})
