# Sentinel - Claude Code Plugin

**An authentication and authorization auditor for your codebase.**

Sentinel finds authentication and authorization bugs that leak one customer's data to another. It specifically checks for issues like:

* Broken object-level authorization / IDOR
* Missing role checks
* Mass assignment
* Tenant-isolation gaps
* Unauthenticated routes
* JWT validation flaws

---

## Who it's for

Sentinel is built for **backend engineers** that work on authn/authz workflows. That engineer doesn't need a generic "security scanner." They need something
that understands the one rule their app lives or dies by: *a caller may only
ever touch data in their own tenant, and privileged actions require the right
role.* Sentinel encodes that rule and checks every endpoint against it.

## What it does

Sentinel ships three components that work at three different moments:

| Component | Type | When it runs |
|-----------|------|--------------|
| `authz-auditor` | Agent | A full, autonomous sweep of an API, producing a ranked findings report that can be called on demand. |
| `auth-review` | Skill | An OWASP API-aligned checklist and reference material, used inline when writing or reviewing endpoints. Also runnable as `/auth-review`. |
| route-edit reminder | Hook | Automatically — after any edit to route/handler code, it nudges you to confirm the auth checks are still in place. |

## Install (under 5 minutes, from a fresh clone)

```bash
git clone https://github.com/adocomplete/sentinel.git
cd sentinel
claude            # start Claude Code inside the repo
```

Then, inside Claude Code:

```
/plugin marketplace add adocomplete/sentinel
/plugin install sentinel@sentinel
```

Confirm the install when prompted. The `authz-auditor` agent, the `auth-review`
skill, and the route-edit hook are now active.

## What I'd do with more time

* Add framework-aware route detectors (the audit is solid on Go `net/http`,
Express, Next.js, and Laravel today, but explicit per-framework parsing would
cut false negatives on unusual routing). 
* Ship a CI mode so `authz-auditor` runs on every pull request and comments findings.
* Add an optional MCP server that reads the live route table or the identity provider's config, so the audit can compare *intended* policy against *implemented* policy instead of inferring intent from the code alone.

## License

MIT.
