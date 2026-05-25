#!/usr/bin/env node
/*
 * Sentinel — PostToolUse hook
 * -----------------------------------------------------------------------------
 * Runs after every Edit / Write / MultiEdit. When the edited file looks like it
 * defines HTTP route handlers, it injects a short reminder asking Claude to
 * confirm the change still enforces authentication and per-tenant authorization
 * before treating it as done.
 */

let raw = "";
process.stdin.on("data", (chunk) => (raw += chunk));
process.stdin.on("end", () => {
  // Any parsing problem: stay silent and exit clean. A hook must never be the
  // reason an edit fails.
  let event;
  try {
    event = JSON.parse(raw || "{}");
  } catch {
    process.exit(0);
  }

  const filePath =
    (event && event.tool_input && event.tool_input.file_path) || "";
  if (!filePath) process.exit(0);

  const path = filePath.toLowerCase();

  // Heuristics: directory and filename conventions that signal HTTP routing or
  // request-handler code across Go, Node/Express, Next.js, and Laravel.
  const routeSignals = [
    /\/handlers?\//,        // Go / general: handlers/
    /\/controllers?\//,     // Laravel / MVC: controllers/
    /\/routes?\//,          // routes/ (Laravel, Express)
    /\/middleware\//,       // auth middleware itself
    /\/api\//,              // Next.js app/api, pages/api, generic /api/
    /handler/,              // *handler*.go, *_handler.*
    /controller/,           // *controller*.*
    /\brouter?\b/,          // router.ts, routes.go
    /route\.(t|j)sx?$/,     // Next.js App Router route.ts / route.js
  ];

  const looksLikeRouteCode = routeSignals.some((re) => re.test(path));
  if (!looksLikeRouteCode) process.exit(0);

  const reminder = [
    `[Sentinel] \`${filePath}\` looks like HTTP route / handler code.`,
    `Before treating this change as complete, verify each affected handler:`,
    `(1) it is reached only through the authentication middleware — not a bare router;`,
    `(2) it confirms the caller's tenant/org owns the specific record it reads or mutates (guard against IDOR);`,
    `(3) it checks the caller's role for privileged actions (delete, admin, billing);`,
    `(4) tenant/org identity comes from the verified token, never from the request body, query, or path;`,
    `(5) request bodies are not bound onto domain models in a way that lets a caller set role, org_id, or id.`,
    `If any of these is unclear, run the auth-review skill or the authz-auditor agent.`,
  ].join(" ");

  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PostToolUse",
        additionalContext: reminder,
      },
    })
  );
  process.exit(0);
});
