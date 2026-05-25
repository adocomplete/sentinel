# Access Control Reference

Deep reference for authorization — checklist items 2–5 in `SKILL.md`. Covers
object-level authorization, function-level authorization, tenant isolation, and
safe input binding. Examples are in Go (`net/http`) and TypeScript, the two
stacks this plugin's demo uses; the patterns transfer to any framework.

---

## 1. Object-level authorization (IDOR / BOLA — OWASP API1)

**The bug:** a handler receives an object id from the client, loads that
object, and returns or mutates it without checking the caller is entitled to
it. The most common and most damaging API vulnerability.

**The test:** for every record loaded by a client-supplied id, ask "what stops
the caller from passing someone else's id?" The answer must be code, not luck.

Incorrect — any authenticated user can read any invoice:

```go
func (h *InvoiceHandler) Get(w http.ResponseWriter, r *http.Request) {
    id := r.PathValue("id")
    invoice, found := h.Store.GetInvoice(id)
    if !found {
        writeError(w, http.StatusNotFound, "invoice not found")
        return
    }
    writeJSON(w, http.StatusOK, invoice) // no ownership check
}
```

Correct — ownership is verified against the token before the record is exposed:

```go
func (h *InvoiceHandler) Get(w http.ResponseWriter, r *http.Request) {
    claims, ok := middleware.ClaimsFrom(r)
    if !ok {
        writeError(w, http.StatusUnauthorized, "unauthorized")
        return
    }
    id := r.PathValue("id")
    invoice, found := h.Store.GetInvoice(id)
    if !found || invoice.OrgID != claims.OrgID {
        // Treat a tenant mismatch as "not found" so the endpoint does not
        // reveal which ids exist in other tenants.
        writeError(w, http.StatusNotFound, "invoice not found")
        return
    }
    writeJSON(w, http.StatusOK, invoice)
}
```

**Prefer 404 over 403** for cross-tenant access: a 403 confirms the id is real.

**Defense in depth:** scope the query itself —
`GetInvoiceForOrg(id, claims.OrgID)` — so the database, not a hand-written
`if`, enforces the boundary. A check you cannot forget beats one you can.

---

## 2. Function-level authorization (OWASP API5)

**The bug:** a sensitive action checks that the caller is *authenticated* but
not that they are *authorized* — no role check. Every logged-in user can do the
admin thing.

Incorrect — any member can delete:

```go
func (h *InvoiceHandler) Delete(w http.ResponseWriter, r *http.Request) {
    id := r.PathValue("id")
    h.Store.DeleteInvoice(id) // authenticated, but no role check
    w.WriteHeader(http.StatusNoContent)
}
```

Correct — the privileged action checks the role:

```go
func (h *InvoiceHandler) Delete(w http.ResponseWriter, r *http.Request) {
    claims, ok := middleware.ClaimsFrom(r)
    if !ok {
        writeError(w, http.StatusUnauthorized, "unauthorized")
        return
    }
    if claims.Role != "admin" {
        writeError(w, http.StatusForbidden, "admin role required")
        return
    }
    // ...also verify org ownership of the target, as in section 1.
}
```

**Better: enforce at registration**, so a new privileged route cannot silently
skip the check:

```go
mux.HandleFunc("DELETE /api/invoices/{id}",
    middleware.RequireAuth(middleware.RequireRole("admin", handler.Delete)))
```

A `RequireRole` wrapper turns "did we remember the check?" into a visible part
of the route table.

---

## 3. Tenant isolation — derive scope from the token, never the request

**The bug:** the handler uses a tenant/org identifier the client supplied (body
field, query parameter, path segment) instead of the one in the verified token.
The client picks the tenant; the client picks the victim.

Incorrect — the new invoice lands in whatever org the body names:

```go
var invoice store.Invoice
json.NewDecoder(r.Body).Decode(&invoice) // invoice.OrgID comes from the client
h.Store.SaveInvoice(invoice)
```

Correct — server-assigned scope overrides anything the client sent:

```go
var invoice store.Invoice
if err := json.NewDecoder(r.Body).Decode(&invoice); err != nil {
    writeError(w, http.StatusBadRequest, "invalid body")
    return
}
invoice.OrgID = claims.OrgID      // authoritative, from the verified token
invoice.ID = h.Store.NextInvoiceID()
h.Store.SaveInvoice(invoice)
```

Rule: **tenant identity is an output of authentication, not an input from the
request.** This applies to filters too — `GET /reports?org_id=...` must ignore
the query value and filter by `claims.OrgID`.

---

## 4. Safe input binding (mass assignment — OWASP API3)

**The bug:** the handler decodes a request body straight onto a domain or
database model. The model has fields the user must not control — `role`,
`org_id`, `id`, `is_admin`, `verified` — and the decoder happily sets them.

Incorrect — a member can promote themselves:

```go
func (h *UserHandler) UpdateMe(w http.ResponseWriter, r *http.Request) {
    var user store.User
    json.NewDecoder(r.Body).Decode(&user) // body can carry "role":"admin"
    user.ID = claims.UserID
    h.Store.SaveUser(user)
}
```

Correct — bind an explicit allow-list, copy onto the loaded record:

```go
func (h *UserHandler) UpdateMe(w http.ResponseWriter, r *http.Request) {
    var input struct {
        Name  string `json:"name"`
        Email string `json:"email"`
    }
    if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
        writeError(w, http.StatusBadRequest, "invalid body")
        return
    }
    existing, _ := h.Store.GetUser(claims.UserID)
    existing.Name = input.Name
    existing.Email = input.Email
    // Role and OrgID are deliberately not updatable here.
    h.Store.SaveUser(existing)
}
```

The TypeScript shape of the same rule — never spread the request body onto a
record:

```ts
// Incorrect: ...req.body can carry role, orgId, id
await db.user.update({ where: { id }, data: { ...req.body } });

// Correct: pick only what is editable
const { name, email } = req.body;
await db.user.update({ where: { id }, data: { name, email } });
```

Use a separate input type / DTO per endpoint. The fields you omit are the
fields you protect.

---

## Review heuristics

- A handler that takes an `{id}` and never compares it to the caller's identity
  is guilty until proven innocent.
- `json.Decode(&domainModel)` / `{ ...req.body }` are smells — look for the
  privileged field that just became writable.
- Any tenant/org value read from `r.Body`, `r.URL.Query()`, or a path segment
  is a tenant-isolation bug until you confirm it is overridden by the token.
- "The UI doesn't show that button" is not access control. Check the API.
