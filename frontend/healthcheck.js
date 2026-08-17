// Targets the login page rather than /admin: unauthenticated requests to
// /admin now redirect there, and hitting it directly keeps the check honest
// about what a healthy container serves to a logged-out visitor. It still
// exercises the session path, since route middleware reads the session on
// every navigation.
fetch('http://localhost:3000/admin/login')
  .then(r => process.exit(r.ok ? 0 : 1))
  .catch(() => process.exit(1))
