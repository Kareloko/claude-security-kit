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
# Only check migrations that CREATE TABLE (not all migrations)
grep -l "CREATE TABLE" supabase/migrations/*.sql 2>/dev/null | \
  xargs grep -L "created_by\|updated_by\|created_at" 2>/dev/null

# Rule 3 — Admin returns 404 not 403 (don't reveal existence)
grep -rn "status: 403\|status(403)" src/app/admin/ src/app/api/admin/ 2>/dev/null

# Rule 4 — SERVICE_ROLE_KEY never in client code
# Two-pass: find files with the key, then exclude server-only files
for f in $(grep -rln "SERVICE_ROLE_KEY" src/app/ src/components/ src/features/ 2>/dev/null); do
  grep -q "'use server'" "$f" || echo "VIOLATION: $f uses SERVICE_ROLE_KEY without 'use server'"
done

# Rule 5 — getUser() always, getSession() never on server
# Two-pass: find files with getSession, exclude those with 'use client'
for f in $(grep -rln "getSession()" src/ 2>/dev/null); do
  grep -q "'use client'" "$f" || echo "VIOLATION: $f uses getSession() in server context"
done

# Rule 6 — Rate limit on expensive endpoints
grep -rL "rateLimit\|checkRateLimit" src/app/api/ai/ src/app/api/auth/ 2>/dev/null

# Rule 7 — Zod validation in server actions
# Find server action files, check each for Zod usage
for f in $(grep -rln "'use server'" src/ 2>/dev/null); do
  grep -q "safeParse\|Schema.parse\|\.parse(" "$f" || echo "WARNING: $f has 'use server' but no Zod validation found"
done

# Rule 8 — Multi-tenancy: queries should filter by user_id/profile_id
# Manual review: list all .select() queries in features that don't chain .eq('user_id')
# NOTE: this is a heuristic, manual review needed for accuracy
grep -rn "\.from(" src/features/ 2>/dev/null | grep "select" | grep -v "user_id\|profile_id\|auth"

# Rule 9 — Env vars fail explicit, never hardcoded fallback
grep -rn "process\.env\.[A-Z_]*\s*||\|process\.env\.[A-Z_]*\s*??" src/ 2>/dev/null | grep -v "|| undefined\|?? undefined\||| null\|?? null\|NODE_ENV"

# Rule 10 — Private layouts = Server Component (not "use client")
grep -l "'use client'" "src/app/(dashboard)/layout.tsx" "src/app/(protected)/layout.tsx" 2>/dev/null

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

# Rule 16 — RLS SELECT includes deleted_at IS NULL (only for tables with soft deletes)
# First find tables that HAVE deleted_at column, then check their SELECT policies
for table in $(grep -l "deleted_at" supabase/migrations/*.sql 2>/dev/null | xargs grep -l "CREATE TABLE" 2>/dev/null); do
  grep "CREATE POLICY.*FOR SELECT" "$table" 2>/dev/null | grep -v "deleted_at IS NULL"
done

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
# Check: createBrowserClient used in files WITHOUT 'use client' (server context)
for f in $(grep -rln "createBrowserClient" src/ 2>/dev/null); do
  grep -q "'use client'" "$f" || echo "VIOLATION: $f uses createBrowserClient without 'use client'"
done
# Check: createServerClient used in files WITH 'use client' (client context)
for f in $(grep -rln "createServerClient" src/ 2>/dev/null); do
  grep -q "'use client'" "$f" && echo "VIOLATION: $f uses createServerClient in 'use client' file"
done

# Bug 7 — Submit buttons without disabled state
grep -rn 'type="submit"\|type=.submit.' src/ 2>/dev/null | grep -v "disabled"

# Bug 8 — Webhooks without signature verification
find src/app/api -path "*webhook*" -name "route.ts" -exec grep -L "verifySignature\|timingSafeEqual\|createHmac" {} \; 2>/dev/null

# Bug 9 — Internal errors exposed to client
grep -rn "error\.message\|error\.stack" src/app/api/ 2>/dev/null | grep "NextResponse\|Response.json"

# Bug 14 — Tables created at runtime without migration
grep -rn "CREATE TABLE" . 2>/dev/null | grep -v "supabase/migrations/\|node_modules/\|.next/"

# --- OWASP Additional Checks ---

# CORS — check for overly permissive Access-Control-Allow-Origin
grep -rn "Access-Control-Allow-Origin\|cors(" src/ next.config.ts 2>/dev/null | grep -i "\*\|origin"

# CSRF — custom API routes with POST that read cookies but no CSRF token
# Server Actions have built-in CSRF protection, but route.ts handlers do NOT
for f in $(find src/app/api -name "route.ts" 2>/dev/null); do
  if grep -q "POST\|PUT\|DELETE\|PATCH" "$f" && grep -q "cookies\|getUser\|getSession" "$f"; then
    grep -q "csrf\|x-csrf\|csrfToken" "$f" || echo "REVIEW: $f handles auth POST without CSRF check"
  fi
done

# XSS — dangerouslySetInnerHTML with user/dynamic content
grep -rn "dangerouslySetInnerHTML" src/ 2>/dev/null | grep -v "DOMPurify\|sanitize"

# XSS — unescaped user input in script tags or eval
grep -rn "eval(\|new Function(" src/ 2>/dev/null | grep -v "node_modules"

# SQL injection — raw SQL with string interpolation
grep -rn "supabase\.rpc\|\.sql\`\|sql(" src/ 2>/dev/null | grep "\${"

# File upload security — check for type validation
grep -rn "upload\|formData.*file\|req\.formData" src/app/api/ 2>/dev/null

# Security headers beyond CSP (X-Frame-Options, HSTS, X-Content-Type-Options)
grep -rn "X-Frame-Options\|Strict-Transport-Security\|X-Content-Type-Options\|Referrer-Policy\|Permissions-Policy" src/middleware.ts next.config.ts 2>/dev/null

# Exposed .env files in public directory
find public/ -name ".env*" -o -name "*.env" 2>/dev/null

# localStorage for tokens (should use httpOnly cookies)
grep -rn "localStorage.*token\|localStorage.*session\|localStorage.*jwt" src/ 2>/dev/null
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
# A policy on table X that SELECTs from table X causes infinite recursion
# Manual check: for each migration with CREATE POLICY, verify the USING/WITH CHECK
# clause does not SELECT FROM the same table the policy is ON
for f in supabase/migrations/*.sql; do
  [ -f "$f" ] || continue
  # Extract table names from CREATE POLICY ... ON public.TABLE
  tables=$(grep -oP 'ON public\.(\w+)' "$f" 2>/dev/null | sed 's/ON public\.//')
  for t in $tables; do
    # Check if same file has FROM public.TABLE in a policy context
    grep -q "FROM public\.$t" "$f" 2>/dev/null && \
      echo "REVIEW $f: policy on '$t' may reference itself (potential infinite recursion)"
  done
done

# signInWithPassword in server action (cookies don't propagate reliably in Next.js 15+)
# Should be client-side with createBrowserClient
for f in $(grep -rln "signInWithPassword" src/ 2>/dev/null); do
  grep -q "'use client'" "$f" || echo "WARNING: $f uses signInWithPassword without 'use client' — cookies may not propagate"
done

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
