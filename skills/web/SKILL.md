---
name: ctf-web
description: Use for authorized Web CTF challenges involving browser flows, HTTP APIs, sessions, injections, uploads, SSRF, deserialization, JWT, SSTI, XXE, source exposure, or request manipulation.
---

# Web CTF

## Recon

1. Navigate to the exact target URL.
2. Capture title, response headers, visible text, forms, links, scripts and API calls.
3. Save an accessibility snapshot when Playwright is available.
4. List network requests, excluding static assets when noisy.
5. Inspect cookies, local/session storage, redirects and auth state.
6. Fetch robots.txt, sitemap.xml and obvious source maps only within scope.

Do not run broad fuzzing before understanding the app.

## Request analysis

For every interesting request record:

- method, URL, parameters and body shape;
- auth headers/cookies;
- status, content type and response length;
- reflected values and server errors;
- related frontend code.

Prefer replaying one controlled mutation at a time.

## Vulnerability routes

### Access control

- Compare anonymous/user/admin states.
- Change IDs one at a time.
- Check object ownership and function-level authorization.
- Test method and content-type overrides only when relevant.

### SQL injection

- Use boolean, error, time and union evidence.
- Prefer manual payloads until the parameter and DB behavior are known.
- Use sqlmap only with a saved request, narrow parameter, bounded threads/time and authorized scope.

### XSS

- Identify sink and execution context.
- Use browser console/DOM evidence.
- For admin-bot challenges, keep callbacks within explicitly authorized hosts.

### SSRF

- First prove outbound request control with a task-owned callback.
- Do not pivot to metadata or unrelated internal services.
- Scope still applies to server-side requests from the challenge; never scan adjacent infrastructure.

### File upload / traversal / inclusion

- Test extension, MIME, magic bytes, double extension, path normalization.
- Verify actual filesystem behavior rather than only upload response.
- Use task-local marker files.

### Command injection

- Prefer harmless arithmetic/file-output or controlled callback proof.
- Do not run destructive commands.

### JWT / sessions

- Decode all claims.
- Check algorithm, key/KID/JWKS, expiry, issuer, audience and role claims.
- Keep token material out of final reports where unnecessary.

### SSTI

- Establish template engine using arithmetic/string probes.
- Progress from evaluation to controlled file/output evidence.

### XXE

- Use a task-controlled callback or harmless local file proof.
- Do not attempt internet exfiltration.

### Deserialization

- Identify language/library and gadget availability.
- Run payloads only inside challenge scope or a disposable analysis container.

### API / GraphQL

- Inspect OpenAPI/GraphQL schemas when exposed.
- Compare schema fields with returned fields.
- Test object-level and property-level authorization.

### HTTP request smuggling

Treat as high-risk. Require clear target authorization and a local/isolated lab. Verify with conservative timing and no shared-user impact.

## Browser state

Use per-task profiles or isolated contexts. Save storage state only when needed. Do not attach the user's normal browser profile to an untrusted challenge.

## Proxy path

Preferred capture:

Playwright network tools, scoped Python proxy, Caido/mitmproxy, or a legitimate Burp extension API.

Never depend on reading Burp's GUI tables when a structured extension/API can return request history and replay results.

## Completion

Record a raw response or replayed exploit artifact containing the exact flag. If the challenge has a submit API, use it and store the accepted response.
