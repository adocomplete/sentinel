# Token & Authentication Reference

Deep reference for authentication — checklist items 1 and 6 in `SKILL.md`.
Covers where authentication is enforced (middleware wiring), JWT validation,
session cookies, OAuth redirects, and secret handling.

Authentication answers "who is calling, and can we trust that claim?"
Authorization (`access-control.md`) answers "may they do this?" An app needs
both; this file is the first half.

---

## 1. Where authentication is enforced — the wiring gap

The most overlooked authentication bug is not in the verification code. It is a
route that was never routed through it.

A handler usually assumes the middleware already ran — it reads the identity
and trusts it. If that route is registered on a bare router, the assumption is
false and the endpoint is anonymous.

Incorrect — one route skips the wrapper every other route uses:

```go
mux.HandleFunc("GET /api/invoices",       middleware.RequireAuth(invoices.List))
mux.HandleFunc("GET /api/invoices/{id}",  middleware.RequireAuth(invoices.Get))
mux.HandleFunc("GET /api/admin/stats",    admin.Stats) // no RequireAuth
```

Correct — every non-public route goes through the same wrapper:

```go
mux.HandleFunc("GET /api/admin/stats", middleware.RequireAuth(admin.Stats))
```

**How to review it:** never read the handler in isolation. Trace each route
from its registration to its handler and confirm the middleware is in the
chain. List the routes that are *intentionally* public (login, signup, health,
webhooks) so the ones that are accidentally public stand out. Grouping routes
under a sub-router that has the middleware applied once is safer than wrapping
each route by hand — a new route added to the group inherits protection.

---

## 2. JWT validation

When a service verifies a JWT, four things must all be true. Missing any one
turns "verified identity" into "attacker-supplied identity."

### 2a. Pin the signing algorithm

The single most important check. The token header names its own algorithm — if
the verifier trusts that field, the attacker controls verification.

- `alg: none` — the attacker declares the token unsigned. The verifier must
  reject it.
- **Algorithm confusion** — a service that verifies RS256 (asymmetric) but does
  not pin the method can be handed an HS256 token; if the verifier feeds the
  *public* key in as an HMAC secret, the attacker — who knows the public key —
  can forge tokens.

Incorrect — the key callback returns the secret for any algorithm:

```go
keyFunc := func(token *jwt.Token) (interface{}, error) {
    return []byte(signingSecret), nil // never inspects token.Method
}
```

Correct — assert the method, and constrain the parser:

```go
keyFunc := func(token *jwt.Token) (interface{}, error) {
    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
        return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
    }
    return []byte(signingSecret), nil
}

token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc,
    jwt.WithValidMethods([]string{"HS256"}))
```

In TypeScript, pass `algorithms` explicitly — never let it default:

```ts
// Incorrect: algorithm is whatever the token claims
jwt.verify(token, secret);

// Correct: the server decides the algorithm
jwt.verify(token, secret, { algorithms: ["HS256"] });
```

### 2b. Verify the signature

Decoding is not verifying. `jwt.decode()` (or splitting on `.` and base64-
decoding) reads claims *without* checking the signature. Use the verifying call
(`jwt.verify`, `ParseWithClaims` with a real keyfunc) for anything trusted.

### 2c. Validate the standard claims

- `exp` — reject expired tokens. (Most libraries do this once you actually
  verify; confirm it is not disabled.)
- `nbf` — reject not-yet-valid tokens.
- `aud` — confirm the token was minted for *this* service, not a sibling that
  shares the secret.
- `iss` — confirm it came from your issuer.

### 2d. Protect the secret / keys

The HMAC secret or private key must come from configuration (environment,
secret manager), never a committed constant. A signing secret in source is a
forge-any-token primitive for anyone with repo access. Rotate on exposure.

---

## 3. Session cookies

If the app uses server sessions instead of (or alongside) JWTs:

- `HttpOnly` — JavaScript cannot read the cookie; blunts XSS token theft.
- `Secure` — the cookie is sent only over HTTPS.
- `SameSite=Lax` or `Strict` — limits CSRF exposure.
- The session id is random and high-entropy; the server can **revoke** it
  (a stateless JWT cannot be revoked before `exp` — a real trade-off).
- Rotate the session id on login to prevent session fixation.

```go
http.SetCookie(w, &http.Cookie{
    Name: "session", Value: id,
    HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
    Path: "/", MaxAge: 3600,
})
```

---

## 4. OAuth / OIDC redirect flows

When the app is an OAuth client:

- **`state`** — generate a random value, store it, and verify it on the
  callback. It binds the callback to the request and blocks CSRF on the login
  flow. A missing or unverified `state` is a real finding.
- **PKCE** — use it for public clients (SPAs, mobile, anything that cannot keep
  a secret). The `code_verifier` / `code_challenge` pair stops authorization-
  code interception.
- **`redirect_uri`** — the provider must match it against an exact allow-list.
  Open redirects here leak authorization codes.
- Validate the ID token like any other JWT (section 2), including `aud` and
  `iss`.

---

## Review heuristics

- Find the token/session verification function first, then trace which routes
  reach it. Auth bugs hide in the wiring as often as in the crypto.
- A keyfunc or `verify` call that does not name an algorithm is a finding.
- `jwt.decode` / manual base64 of a token, used for anything trusted, is a
  finding — it skips signature verification.
- A signing secret as a string literal in the repo is a finding.
- Missing `aud` lets a token from a sibling service authenticate here.
