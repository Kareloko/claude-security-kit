# Incident Response Playbook

> **Read WHEN** a security incident occurs or is suspected: breach, unauthorized access, data leak, compromised keys, active attack, ransomware.
> **Goal:** the first 60 minutes determine the damage. Don't improvise.

---

## Quick Classification

| Severity | Example | Immediate Action |
|----------|---------|------------------|
| **SEV-1 Critical** | User data exposed, DB accessed by external, service_role leaked | Follow FULL playbook NOW |
| **SEV-2 High** | Successful brute force, exploited XSS, defacement | Contain + rotate + notify in 24h |
| **SEV-3 Medium** | Isolated auth failure, suspicious logs no confirmed impact | Investigate <4h, document |
| **SEV-4 Low** | Attack attempts blocked by rate limit | Log, review trend |

---

## The First 60 Minutes (SEV-1/SEV-2)

### Minute 0-5 — DETECT and DECLARE

1. **Confirm incident** (not false alarm)
2. **Open single communication channel** for all updates with timestamps
3. **Name Incident Commander** (yourself by default)

### Minute 5-15 — CONTAIN

Stop the damage. Even without full understanding.

```bash
# If keys leaked -> ROTATE ALL keys immediately
# Supabase Dashboard -> Settings -> API -> Generate new keys
# Vercel -> Settings -> Environment Variables -> update
# Redeploy to pick up new keys

# If DB accessed -> block attacker IPs
# If endpoint compromised -> disable via feature flag
UPDATE feature_flags SET enabled = false WHERE feature = 'compromised_endpoint';

# If user account compromised -> force global logout
# supabase.auth.admin.signOut(userId, 'global')

# If admin account compromised -> change password + enforce MFA
```

### Minute 15-30 — ASSESS SCOPE

```sql
-- How many records accessed outside normal patterns?
SELECT COUNT(*), MIN(created_at), MAX(created_at)
FROM security_logs
WHERE type IN ('permission_denied', 'suspicious_request')
AND created_at > now() - interval '24 hours';

-- Unusual IPs?
SELECT ip, COUNT(*) as hits
FROM security_logs
WHERE created_at > now() - interval '24 hours'
GROUP BY ip ORDER BY hits DESC LIMIT 20;

-- Potentially compromised users?
SELECT user_id, COUNT(DISTINCT ip) as ip_count
FROM active_sessions
WHERE created_at > now() - interval '24 hours'
GROUP BY user_id
HAVING COUNT(DISTINCT ip) > 3
ORDER BY ip_count DESC;
```

Answer:
- [ ] How many users affected?
- [ ] What type of data? (PII, financial, medical, minors, credentials)
- [ ] Since when? (first malicious activity timestamp)
- [ ] Entry vector? (phishing, CVE, IDOR, insider)

### Minute 30-45 — ERADICATE

Close the entry vector.

- If CVE in dependency -> `npm update` + redeploy
- If weak password -> force reset for all affected users
- If broken RLS -> migration fix + redeploy
- If unauthenticated endpoint -> fix + redeploy
- If phishing against you -> change password + MFA + review connected OAuth apps
- If insider -> revoke all access for that account

### Minute 45-60 — NOTIFY

**Order:**
1. **Affected users** (if SEV-1 with exposed PII) — email + in-app
2. **Data protection authority** (SEV-1 only)
   - Most jurisdictions require notification within 48-72h
   - Examples: GDPR (72h), Peru Ley 29733 (48h), COPPA (if minors)
3. **Clients/partners** if applicable
4. **Public** only if inevitable or already in press

---

## User Notification Template (SEV-1)

```
Subject: Important: Security incident affecting your {SERVICE} account

Dear {NAME},

On {DATE}, we detected a security incident that may have exposed
the following data from your account: {SPECIFIC DATA LIST}.

What we did:
- Detected the incident on {DATE-TIME}
- Contained unauthorized access on {DATE-TIME}
- Rotated all system credentials
- Notified relevant authorities

What you should do:
1. Change your password immediately: {LINK}
2. Enable two-factor authentication: {LINK}
3. Review recent activity in your account
4. If you reuse this password elsewhere, change it there too

Information that was NOT exposed:
{LIST OF WHAT'S SAFE}

We are available for any questions at: {SECURITY_EMAIL}
```

---

## Post-Incident (within 7 days)

### Mandatory Postmortem

Create `docs/incidents/{YYYY-MM-DD}-{slug}.md`:

1. **Complete timeline** — every action with timestamp
2. **Root cause** — 5 whys (the last "why" is the real one)
3. **Impact** — users, data, duration, cost
4. **What worked well** during response
5. **What failed** during response
6. **Action items** with owner + deadline
7. **New rule** — the documented error never happens again

### Preventive Rotation

Even without evidence of compromise:
- [ ] Rotate ALL API keys of affected service
- [ ] Force password reset for all admins
- [ ] Review active OAuth tokens
- [ ] Invalidate all active sessions

---

## Forensic Toolkit

```bash
# Download Vercel logs
vercel logs {project} --since 7d > incident-vercel.log

# Extract critical events
grep -E "401|403|429|500" incident-vercel.log | sort | uniq -c | sort -rn > incident-errors.txt

# Hash logs for chain of custody
sha256sum incident-*.log > incident-checksums.txt

# Store everything encrypted offsite
zip -e incident-{DATE}.zip incident-*.* -P {password}
```

---

## Anti-Patterns in Incident Response

- **DON'T delete logs** — they're legal evidence
- **DON'T lie to users** about scope — if you discover more later, worse image
- **DON'T publicly blame** vendors without evidence — legal risk
- **DON'T hotfix under pressure** without testing — worsens the incident
- **DON'T resolve without postmortem** — the error recurs
- **DON'T notify without legal counsel** if SEV-1 with 100+ affected users
