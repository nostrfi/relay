// Run from frontend/ on the branch:  node diagnose-overview.mjs
// Prints where the overview page fails, without needing a browser.
const base = process.env.BASE ?? 'http://localhost:3000/admin'

const paths = ['/', '/dashboard', '/dashboard/events', '/dashboard/configuration', '/dashboard/moderation']
for (const path of paths) {
  try {
    const r = await fetch(base + path, { redirect: 'manual' })
    const body = await r.text()
    const title = (body.match(/<title>([^<]*)<\/title>/) || [])[1] ?? ''
    const err = (body.match(/"statusMessage":"([^"]{0,160})/) || [])[1]
    console.log(`${path.padEnd(26)} ${r.status} ${r.headers.get('location') ?? ''} ${title} ${err ? '\n    ERROR: ' + err : ''}`)
  } catch (e) {
    console.log(`${path.padEnd(26)} REQUEST FAILED: ${e.message}`)
  }
}
