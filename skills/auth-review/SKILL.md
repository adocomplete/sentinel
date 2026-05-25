---
name: auth-review
description: >-
  Authentication and authorization review methodology for backend APIs. Use
  when adding, changing, or reviewing API endpoints, middleware, or token
  handling. Provides a per-endpoint checklist and OWASP API Security
  Top 10 aligned reference material for access control and token validation.
---

# Auth Review

A working method for getting authorization right on a backend API — whether you
are writing a new endpoint, reviewing a diff, or auditing an existing handler.

For a full autonomous sweep of an entire codebase, use the `authz-auditor`
agent instead. This skill is for focused, in-the-loop review of the code in
front of you.

## The invariant

Most API breaches are not exotic. They are a missing `if`. In a multi-tenant
app, two rules hold for every authenticated endpoint:

1. **A caller may only read or modify data that belongs to their own tenant
   (org / account / workspace).**
2. **A privileged action may only be performed by a caller with the required
   role.**

Every check below exists to defend one of those two rules.

## Per-endpoint checklist

Apply this to each endpoint you write or review. The first "no" is a finding.

1. **Authentication is wired up.** The route is registered *through* the auth
   middleware, not on a bare router. Trace it — do not assume. A handler that
   reads identity from the request without the middleware having verified it
   is unauthenticated. See `references/token-validation.md`

2. **Object-level authorization.** When the handler loads a record by an id it
   received (path, query, or body), it verifies the caller owns that record or
   shares its tenant *before* returning or mutating it. A bare
   `GET /resource/{id}` lookup with no ownership check is IDOR (OWASP API1).
   Prefer "not found" over "forbidden" so you don't leak which ids exist.
   See `references/access-control.md`

3. **Function-level authorization.** For destructive or administrative actions
   (delete, admin endpoints, billing, user management), the handler checks the
   caller's **role** and not merely that they are logged in (OWASP API5).
   See `references/access-control.md`

4. **Tenant scope comes from the token.** The org/tenant identifier is read
   from the verified token/session, never from a request body, query string,
   or path segment the client controls. If a client can name the org, the
   client can pick a victim. See `references/access-control.md`

5. **Input binding is safe.** The handler does not decode a request body
   straight onto a domain or database model. It binds an explicit allow-list of
   editable fields, so a caller cannot set `role`, `org_id`, `id`, `is_admin`,
   or `verified` (mass assignment, OWASP API3). See `references/access-control.md`

6. **Token validation is sound.** The verification code pins the signing
   algorithm (rejects `none` and algorithm confusion), verifies the signature,
   and validates `exp` / `nbf` / `aud` / `iss`. Session cookies are `HttpOnly`,
   `Secure`, and `SameSite`. Secrets are strong and not hardcoded.
   See `references/token-validation.md`

7. **Client-side checks are not the control.** If the UI hides an action for
   non-privileged users, the API must still enforce it. A UI gate without a
   server gate is cosmetic.

## How to use this skill

**Reviewing existing code:** Walk the checklist top to bottom for each handler
in scope. Report findings with `file:line`, a concrete exploit, and the minimal
fix. Pull in a reference file when you need the precise pattern or want to show
correct vs. incorrect code.

**Writing new code:** Treat the checklist as acceptance criteria. The two that
are easiest to forget — and most expensive to miss — are #2 (object-level) and
#4 (tenant scope). Decide both before writing the handler body.

**Read references on demand.** Keep this file as the index. Load
`references/access-control.md` for authorization questions (#2–#5) and
`references/token-validation.md` for authentication questions (#1, #6). Each
has correct/incorrect code in Go and TypeScript.

## Output when reviewing

Lead with a one-line verdict. Then, per finding: severity
(Critical / High / Medium / Low), the OWASP API category, `file:line`, what is
wrong, how it is exploited, and the fix. Name the endpoints that are already
correct — it sharpens the real findings and shows you read the whole thing.
