// The landing page is public again (nostrfi/workspace#46), so /admin is a
// 200 rather than a redirect. It still exercises the session path, since
// route middleware reads the session on every navigation.
fetch('http://localhost:3000/admin')
  .then(r => process.exit(r.ok ? 0 : 1))
  .catch(() => process.exit(1))
