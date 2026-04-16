# Security Fundamentals — CIA Triad + Glossary + Severity

> Reference loaded by `saas-security-audit` skill. Contains the formal vocabulary and classification system for security audits.

---

## CIA Triad (3 pillars of information security)

- **Confidentiality** — only authorized people access the information.
  In your stack: RLS + encryption at rest (managed by Supabase/cloud provider) + HTTPS + RBAC + MFA. For app-level field encryption: AES-256-GCM in your code.
- **Integrity** — information is not modified without authorization.
  In your stack: webhook signature verification + Zod validation before writes + audit trail.
- **Availability** — information is accessible when needed.
  In your stack: Vercel/Supabase uptime + rate limiting (anti-DDoS) + backups.

**Complementary concepts:**

- **Authentication** — who are you? (Supabase Auth + MFA TOTP)
- **Authorization** — what can you do? (RLS policies + roles in profiles)
- **Non-Repudiation** — you can't deny you did it (audit log with userId + timestamp + IP + signature)

---

## Operational Glossary

| Term | Definition |
|------|-----------|
| Vulnerability | Exploitable weakness (table without RLS, endpoint without auth check) |
| Threat | Agent/event that can exploit it (attacker, human error) |
| Risk | Probability x Impact (IDOR on patients table = HIGH) |
| Exploit | Code/technique that takes advantage of a specific vulnerability |
| Payload | Useful load executed by the exploit once inside |
| Zero Day | Vulnerability with no known patch |
| Attack Vector | Path to the target (phishing -> malware -> lateral movement -> DB) |
| Attack Surface | Everything exposed to probe (domains, APIs, forms, webhooks, Storage) |

---

## Severity Classification for Audit Reports

- **CRITICAL** — unauthorized access to other users' data, RCE, total auth bypass. Immediate fix. Do not deploy until resolved.
- **HIGH** — IDOR, SQL injection, stored XSS, session hijacking possible. Fix in 24-48h.
- **MEDIUM** — CSRF, missing headers, info disclosure in errors. Fix in current sprint.
- **LOW** — cookies without secure flag in dev, outdated dependencies. Fix in next maintenance cycle.
- **INFO** — best practices not implemented with no immediate risk. Document and plan.

---

## Mapping to Next.js + Supabase Stack

| Concept | Implementation |
|---------|---------------|
| Confidentiality | RLS + AES-256-GCM + HTTPS |
| Integrity | Zod validation + webhook signatures |
| Availability | Vercel Edge + Supabase + rate limit |
| Authentication | Supabase Auth + MFA TOTP |
| Authorization | RLS policies + roles in profiles |
| Non-Repudiation | security_logs table + audit trail |
| Reduce surface | CSP headers + Permissions-Policy |
| Risk management | npm audit + OWASP ZAP in CI/CD |

---

## Session Hijacking Defense

Session hijacking = attacker steals cookie/token and enters without password. Real vectors: XSS reading cookies, MITM, info-stealer malware, session fixation, OAuth consent phishing.

**Base defense (cookie configuration):**
- Cookies: `httpOnly` + `secure` + `sameSite=lax` (Supabase Auth sets this by default)
- Strict CSP blocking external scripts
- Never `dangerouslySetInnerHTML` with user input (or sanitize with DOMPurify)
- Refresh token rotation (active by default in Supabase Auth)

**Advanced defense — device fingerprinting:**

For critical operations (plan change, account deletion, data transfer), verify session integrity by comparing User-Agent + IP against fingerprint stored at login.

**Important caveat:** IP-based fingerprinting has false positives on mobile networks (WiFi to cellular switches IP frequently). Use it to **flag for review** or require re-auth, not to hard-block. Consider comparing IP range/ASN instead of exact IP for softer detection.

```sql
CREATE TABLE active_sessions (
  id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
  fingerprint_hash text NOT NULL,
  user_agent text,
  ip text,
  created_at timestamptz DEFAULT now() NOT NULL,
  last_active_at timestamptz DEFAULT now() NOT NULL
);

ALTER TABLE active_sessions ENABLE ROW LEVEL SECURITY;
CREATE POLICY "users_own_sessions" ON active_sessions
  FOR ALL USING (auth.uid() = user_id);
CREATE INDEX idx_active_sessions_user ON active_sessions(user_id, created_at DESC);
```

**Automatic cleanup** (via daily cron):
```sql
DELETE FROM active_sessions WHERE last_active_at < now() - interval '30 days';
```

**Give users:** a "close all sessions" button that deletes all rows for their `user_id` and invalidates tokens via `supabase.auth.admin.signOut(userId, 'global')`.

---

## Re-authentication for Destructive Actions

Operations that destroy data or change identity require **password again**, even if session is active. If an attacker steals the session, they can't destroy the account with one click.

**Operations that ALWAYS require re-auth:**
- Delete account (hard delete)
- Change primary email
- Change password
- Disable MFA
- Transfer ownership of critical resource
- Export complete data (GDPR portability)
- Revoke sessions on other devices

**Pattern:**
```typescript
// Re-auth before destructive action
const { error: reauthError } = await supabase.auth.signInWithPassword({
  email: user.email!,
  password: formData.get('password') as string,
})
if (reauthError) {
  logSecurityEvent('REAUTH_FAILED', { userId: user.id, action: 'delete_account' })
  return { error: 'Incorrect password' }
}
// Proceed with destructive action...
```

Plus textual confirmation: user must type exact phrase like "DELETE MY ACCOUNT" to prevent accidental clicks.
