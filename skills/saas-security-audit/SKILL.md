---
name: saas-security-audit
description: "Production security auditor for Next.js + Supabase SaaS. Verifies RLS, auth hardening, OWASP Top 10, session hijacking defense, legal compliance (GDPR/Ley 29733/COPPA), secret scanning, rate limiting, CSP, and 30+ battle-tested rules from real production incidents. Use when you say 'security audit', 'check my security', 'revisa seguridad', 'audit RLS', 'check auth'. For deep offensive audit (Burp/ZAP/pentest), use flag --deep."
---

# SaaS Security Audit — Production-Grade Checker

> **Role:** Principal Security Engineer with 30+ years. Thinks like an attacker. Every table without RLS is a breach. Every exposed key is an incident.
> **Philosophy:** Universal standards are the floor, not the ceiling. Real production bugs teach the best lessons.

## When to use

**Default mode:**
- Finished a feature with auth/RLS/rate-limit
- Before merging to dev/main
- Part of `saas-security-review` orchestrator flow
- Suspect a security bug

**Deep mode (`--deep`):**
- Deep audit of your own SaaS (medical/financial/kids data)
- Paid audit for external client
- Bug bounty preparation
- Post-incident forensic analysis
- Loads `${CLAUDE_PLUGIN_ROOT}/references/offensive-security.md`

---

## EXECUTION PROTOCOL

### Phase 0 — Load context

Read the project's CLAUDE.md for project-specific security rules. Then load:
1. `${CLAUDE_PLUGIN_ROOT}/references/security-fundamentals.md` (CIA triad + glossary + severity)
2. If `--deep`: also `${CLAUDE_PLUGIN_ROOT}/references/offensive-security.md`

---

### Phase 1 — Core Security Rules (18 checks)

```bash
# Rule 1 — RLS on ALL tables
grep -rL "ENABLE ROW LEVEL SECURITY" supabase/migrations/ 2>/dev/null | grep -v "\.down\.sql"

# Rule 2 — Audit trail on business tables (created_by, updated_by)
grep -rL "created_by\|updated_by" supabase/migrations/*.sql 2>/dev/null

# Rule 3 — Admin returns 404 not 403 (don't reveal existence)
grep -rn "status: 403\|status(403)" src/app/admin/ src/app/api/admin/ 2>/dev/null

# Rule 4 — SERVICE_ROLE_KEY never in client code
grep -rn "SERVICE_ROLE_KEY" src/app/ src/components/ src/features/ 2>/dev/null | grep -v "'use server'\|route.ts\|actions/"

# Rule 5 — getUser() always, getSession() never on server
grep -rn "getSession()" src/ 2>/dev/null | grep -v "browserClient\|'use client'"

# Rule 6 — Rate limit on expensive endpoints
grep -rL "rateLimit\|checkRateLimit" src/app/api/ai/ src/app/api/auth/ 2>/dev/null

# Rule 7 — Zod validation in server actions (first line)
grep -rn "'use server'" src/ -A 10 2>/dev/null | grep -B 10 "formData\|body" | grep -v "Schema.parse\|safeParse"

# Rule 8 — Multi-tenancy double layer (RLS + code check)
grep -rn "\.eq('id'" src/features/ 2>/dev/null | grep -v "\.eq('user_id'\|profile_id"

# Rule 9 — Env vars fail explicit, never hardcoded fallback
grep -rn "process\.env\.[A-Z_]* ||" src/ 2>/dev/null | grep -v "|| undefined\||| null"

# Rule 10 — Private layouts = Server Component (not "use client")
grep -l "'use client'" src/app/\(dashboard\)/layout.tsx src/app/\(protected\)/layout.tsx 2>/dev/null

# Rule 11 — middleware.ts exact name
ls src/middleware.ts 2>/dev/null || ls middleware.ts 2>/dev/null

# Rule 12 — Anti-SSRF whitelist in proxy endpoints
grep -rn "fetch(url\|fetch(req" src/app/api/ 2>/dev/null | grep -v "ALLOWED_DOMAINS\|allowlist\|whitelist"

# Rule 13 — CSP header present
grep -rn "Content-Security-Policy" src/middleware.ts next.config.ts 2>/dev/null

# Rule 14 — redirectTo validated as local path
grep -rn "redirectTo\|redirect_to" src/ 2>/dev/null | grep -v "startsWith('/')"

# Rule 15 — Login uses generic error message (no email enumeration)
grep -rn "email no existe\|email invalido\|usuario no registrado\|user not found\|email not registered" src/app/ 2>/dev/null

# Rule 16 — RLS SELECT includes deleted_at IS NULL
grep -rn "CREATE POLICY.*FOR SELECT" supabase/migrations/*.sql 2>/dev/null | grep -v "deleted_at IS NULL"

# Rule 17 — CSP with nonce, no 'unsafe-inline' in script-src
grep -rn "'unsafe-inline'" next.config.ts src/middleware.ts 2>/dev/null | grep -i "script-src"

# Rule 18 — Feature gating via DB, not hardcoded plan checks
grep -rn "plan === 'pro'\|plan === 'premium'" src/ 2>/dev/null
```

For each violation: report file:line, severity (CRITICAL/HIGH/MEDIUM/LOW), concrete fix with code.

---

### Phase 2 — Anti-Bug Rules (14 most common causes)

```bash
# Bug 3 — "use client" overuse (should be <30% of pages)
find src/app -name "page.tsx" -exec grep -l "'use client'" {} \; 2>/dev/null | wc -l

# Bug 4 — NEXT_PUBLIC_ exposing secrets
grep -rn "NEXT_PUBLIC_" src/ 2>/dev/null | grep -iE "SECRET|PRIVATE|SERVICE|ADMIN"

# Bug 5 — Types out of sync with Supabase schema
# Compare migration dates vs types/supabase.ts modification date

# Bug 6 — Supabase client mixed (server in client, client in server)
grep -rn "createBrowserClient\|createServerClient" src/ 2>/dev/null | awk -F: '{print $1}' | sort -u

# Bug 7 — Submit buttons without disabled state
grep -rn 'type="submit"\|type=.submit.' src/ 2>/dev/null | grep -v "disabled"

# Bug 8 — Webhooks without signature verification
find src/app/api -path "*webhook*" -name "route.ts" -exec grep -L "verifySignature\|timingSafeEqual\|createHmac" {} \; 2>/dev/null

# Bug 9 — Internal errors exposed to client
grep -rn "error\.message\|error\.stack" src/app/api/ 2>/dev/null | grep "NextResponse\|Response.json"

# Bug 14 — Tables created at runtime without migration
grep -rn "CREATE TABLE" src/ 2>/dev/null | grep -v supabase/migrations/
```

---

### Phase 2.5 — Legal Compliance & Defensive Automation

```bash
# Account deletion endpoint (GDPR art. 17 / Ley 29733)
test -f src/app/api/account/delete/route.ts && echo "OK" || echo "MISSING: /api/account/delete"

# Data export endpoint (GDPR art. 20)
test -f src/app/api/account/export/route.ts && echo "OK" || echo "MISSING: /api/account/export"

# Re-authentication for destructive operations
grep -rn "signInWithPassword" src/features/account/ src/app/api/account/ 2>/dev/null

# Feature flags table (kill switch)
grep -rn "feature_flags" supabase/migrations/*.sql 2>/dev/null | head -3

# security.txt published
test -f public/.well-known/security.txt && echo "OK" || echo "MISSING: security.txt"

# Dependabot configuration
test -f .github/dependabot.yml && echo "OK" || echo "MISSING: dependabot.yml"

# CodeQL SAST workflow
test -f .github/workflows/codeql.yml && echo "OK" || echo "MISSING: CodeQL"

# Secret scanning workflow
grep -rln "trufflehog\|gitleaks" .github/workflows/ 2>/dev/null || echo "MISSING: secret scanning"

# SIEM lite cron
grep -rn "security-alerts\|detect_brute_force" src/app/api/cron/ 2>/dev/null | head -3

# Backup offsite workflow
grep -rln "pg_dump.*SUPABASE\|pg_dump.*DATABASE" .github/workflows/ 2>/dev/null || echo "CONSIDER: offsite backup"
```

Severity:
- Missing `/api/account/delete` -> **HIGH** (legal non-compliance)
- Missing `security.txt` -> **LOW** (missed defensive opportunity)
- Missing Dependabot -> **MEDIUM** (undetected vulnerabilities)
- Missing SIEM -> **MEDIUM** (attacks go undetected)
- Missing backup offsite -> **HIGH** if SaaS has real user data

---

### Phase 3 — Battle-Tested Bug Detection

Checks for real bugs discovered in production (documented via postmortems):

```bash
# Env vars with trailing LF (Upstash/Stripe crash silently)
# If scripts use `vercel env add` → warn about printf '%s' pattern

# Cron handlers without global try/catch (partial silent failures)
for f in src/app/api/cron/*/route.ts; do
  [ -f "$f" ] && ! grep -q "try {" "$f" && echo "MISSING try/catch: $f"
done

# .env.example drift (vars used but not documented)
comm -23 \
  <(grep -rhoE 'process\.env\.[A-Z_]+' src/ 2>/dev/null | sed 's/process\.env\.//' | sort -u) \
  <(grep -oE '^[A-Z_]+' .env.example 2>/dev/null | sort -u)

# RLS policy self-reference (infinite recursion)
grep -rn "CREATE POLICY" supabase/migrations/*.sql -A 5 2>/dev/null | \
  awk '/ON public\.([a-z_]+)/{t=$3} /FROM public\.([a-z_]+)/{if($3==t) print FILENAME": potential recursion on "t}'

# signInWithPassword in server action (cookies don't propagate reliably)
grep -rn "signInWithPassword" src/ 2>/dev/null | grep -v "'use client'\|browserClient"

# CSP nonce + static page = blank page
if grep -q "Content-Security-Policy.*nonce" src/middleware.ts 2>/dev/null; then
  grep -l "await headers()" src/app/layout.tsx 2>/dev/null || echo "WARNING: CSP nonce requires headers() in layout for dynamic render"
fi

# Signup without profile rollback (orphaned auth.users)
grep -rn "auth\.signUp\|admin\.createUser" src/ -A 20 2>/dev/null | grep -v "DELETE\|catch.*delete"
```

---

### Phase 4 — CIA Triad Classification

For each finding, classify by CIA pillar:

| Pillar Violated | Examples |
|----------------|----------|
| Confidentiality | Missing RLS, SERVICE_ROLE in client, data of other users accessible |
| Integrity | Webhook without signature, missing audit trail, signup without rollback |
| Availability | No rate limiting, no backup, cron without try/catch |

Severity scale:
- **CRITICAL** — unauthorized data access, RCE, total auth bypass. Fix NOW.
- **HIGH** — IDOR, SQL injection, session hijacking possible. Fix in 24-48h.
- **MEDIUM** — missing headers, CSRF, info disclosure. Fix this sprint.
- **LOW** — cookies without secure in dev, outdated deps. Fix next cycle.
- **INFO** — best practice not implemented, no immediate risk. Plan it.

---

### Phase 5 — Deep Audit (only with `--deep` flag)

Load `${CLAUDE_PLUGIN_ROOT}/references/offensive-security.md` and additionally run:

1. Burp/ZAP execution against preview deployment
2. ffuf fuzzing of discovered endpoints
3. Manual IDOR attempts (swap UUIDs in requests)
4. Attack surface verification (subdomain enum, directory enum)
5. Generate professional report using appropriate template:
   - **WordPress sites** -> `${CLAUDE_PLUGIN_ROOT}/references/audit-templates/wordpress-external-audit.md`
   - **Next.js+Supabase SaaS** -> internal format with CIA triad (this skill)

**Stack detection** (before choosing template):
```bash
curl -I https://{DOMAIN}
curl -s https://{DOMAIN} | grep -iE "wp-content|wp-includes|_next/static|__NEXT_DATA__"
```

---

## REPORT FORMAT

```markdown
# Security Audit Report — [project name]
Date: YYYY-MM-DD
Scope: [files/modules reviewed]
Mode: [standard | --deep]

## Summary
- CRITICAL: N (fix immediately, do not deploy)
- HIGH: N (fix in 24-48h)
- MEDIUM: N (fix this sprint)
- LOW: N (fix next cycle)
- INFO: N (plan it)

## CRITICAL Findings

### [RULE-X] Description
- **File:** src/app/api/foo/route.ts:42
- **CIA Pillar:** Confidentiality / Integrity / Availability
- **Evidence:** [grep output / code snippet]
- **Why it matters:** [concrete impact]
- **Fix:**
  ```typescript
  [correct code]
  ```

## HIGH Findings
[...]

## Rules Verified OK
- [x] Rule 1: RLS enabled on all tables
- [x] Rule 5: getUser() used consistently
[...]

## Recommended Next Steps
1. Fix critical X before any merge
2. Run full pre-launch review when ready for production
```

---

## ANTI-PATTERNS

- **Don't soften findings** — if it's critical, say critical
- **Don't invent violations** — only report what grep/reading confirms
- **Don't run destructive exploits** — only in `--deep` mode with explicit permission
- **Don't modify code directly** — report findings, user decides what to fix
- **Do give the concrete fix** — not "you should improve X", but the exact code
