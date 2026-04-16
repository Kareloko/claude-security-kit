# Claude Security Kit

> Production-grade security toolkit for Next.js + Supabase SaaS apps — built for Claude Code.

**2 skills + 4 playbooks** that protect your SaaS from OWASP Top 10, enforce legal compliance (GDPR/LATAM), and automate defensive security — all from your terminal.

---

## What you get

| Component | Description |
|-----------|-------------|
| `saas-security-audit` | 30+ battle-tested security checks: RLS, auth, CSP, OWASP, session hijacking, legal compliance, secrets scanning |
| `saas-security-review` | Daily orchestrator: code quality + security audit + universal OWASP check in sequence |
| `security-fundamentals.md` | CIA triad, severity glossary, session fingerprint, re-auth patterns |
| `offensive-security.md` | Ethical hacking playbook: Burp, Kali, ZAP, bug bounty, forensics |
| `incident-response.md` | Minute-by-minute playbook for the first 60 minutes of a breach |
| `security-automation.md` | One-time setup: Dependabot, CodeQL, DMARC, SIEM, encrypted backups |
| `wordpress-audit.md` | Professional audit template for WordPress client sites |

---

## Install

```bash
claude plugin install github:Kareloko/claude-security-kit
```

Or clone manually:

```bash
git clone https://github.com/Kareloko/claude-security-kit.git ~/.claude/plugins/claude-security-kit
```

---

## Usage

### Daily review (after finishing a feature)

```
You: "security review"
```

Runs **simplify** (code quality) -> **saas-security-audit** (30+ checks) -> **universal OWASP check** in sequence. Reports blockers with concrete fixes.

### Security audit (before launch or sensitive features)

```
You: "security audit"
```

Runs all phases including legal compliance checks (GDPR endpoints, Dependabot, DMARC, feature flags, backups).

### Deep offensive audit (pentest-style)

```
You: "security audit --deep"
```

Adds Burp/ZAP/ffuf offensive techniques. Detects stack automatically (Next.js vs WordPress) and uses the right audit template.

---

## What it checks (30+ rules)

### Core Security (Phase 1)
- RLS enabled on ALL Supabase tables
- `getUser()` always, `getSession()` never on server
- `SERVICE_ROLE_KEY` never in client code
- Zod validation as first line in server actions
- Rate limiting on expensive endpoints (AI, auth, external APIs)
- CSP headers with nonce (no `unsafe-inline` in script-src)
- Admin routes return 404, never 403
- `redirectTo` validated as local path (anti-open-redirect)
- Generic login error messages (anti-email-enumeration)
- Soft deletes: RLS SELECT includes `deleted_at IS NULL`
- Multi-tenancy double layer (RLS + explicit code check)
- Webhook signature verification
- No internal errors exposed to client

### Anti-Bug Rules (Phase 2)
- `"use client"` not overused (Server Components by default)
- `NEXT_PUBLIC_` not exposing secrets
- Supabase types synced with schema
- Submit buttons have `disabled={isPending}`
- Tables created via migrations, never at runtime

### Legal Compliance (Phase 2.5)
- `/api/account/delete` endpoint (GDPR art. 17 / Ley 29733 Peru)
- `/api/account/export` endpoint (GDPR art. 20)
- Re-authentication for destructive actions
- Feature flags table (kill switch without redeploy)
- `security.txt` published
- Dependabot + CodeQL + TruffleHog configured
- SIEM lite cron for security event monitoring
- Encrypted offsite backup

### Battle-Tested Bugs (Phase 3)
Real production bugs from actual SaaS apps:
- Env vars with trailing `\n` (Upstash/Stripe silent crash)
- Cron handlers without global try/catch (silent failures)
- `.env.example` drift from actual code
- RLS policy self-reference (infinite recursion)
- `signInWithPassword` in server action (cookies don't propagate)
- CSP nonce + static page = blank page
- Signup without profile rollback (orphaned auth.users)

### CIA Classification (Phase 4)
Every finding classified by:
- **Confidentiality** / **Integrity** / **Availability** pillar
- **Severity**: CRITICAL > HIGH > MEDIUM > LOW > INFO

---

## Report example

```
# Security Audit Report — my-saas-app
Date: 2026-04-16
Verdict: DO NOT MERGE

## Summary
- CRITICAL: 1 (RLS missing on payments table)
- HIGH: 2 (no account deletion endpoint, webhook without signature)
- MEDIUM: 3 (missing CSP, no rate limit on /api/ai, Dependabot not configured)

## CRITICAL: RLS missing on payments table
- File: supabase/migrations/20260401_payments.sql
- CIA: Confidentiality
- Fix: ALTER TABLE payments ENABLE ROW LEVEL SECURITY; ...
```

---

## Stack

Built for:
- **Next.js 15+** (App Router, Server Components, Server Actions)
- **Supabase** (PostgreSQL + Auth + RLS + Storage)
- **Vercel** (deployment, crons, environment)
- **TypeScript** (strict mode)

Works with any Next.js + Supabase project following standard conventions.

---

## Born from real bugs

This toolkit was born from **real production incidents** across 5+ SaaS apps serving LATAM markets (medical, financial, education, kids data). Every rule exists because a real bug happened and was documented so it never happens again.

> _"The error that gets documented never returns."_

---

## Contributing

Found a security pattern we're missing? Open an issue or PR:

1. Add the check to `saas-security-audit/SKILL.md` (appropriate phase)
2. If it's a new reference, add to `references/`
3. If it's a battle-tested bug, add to Phase 3 with context

---

## License

MIT — use it, fork it, improve it, share it.

---

**Made with battle scars by [Somar Creaciones](https://github.com/Kareloko)**
