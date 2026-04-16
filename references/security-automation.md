# Security Automation — Set Up Once, Protected Forever

> Configure once per project. Zero maintenance after. These protect you 24/7 automatically.

---

## 1. GitHub Dependabot + Secret Scanning

`.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 5
    labels:
      - "dependencies"
    groups:
      minor-and-patch:
        update-types: ["minor", "patch"]

  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "monthly"
```

**Activate in GitHub UI:** Settings -> Code security -> Enable: Dependency graph, Dependabot alerts, Dependabot security updates, Secret scanning, Push protection.

### CodeQL (Free SAST)

`.github/workflows/codeql.yml`:

```yaml
name: CodeQL
on:
  push:
    branches: [main, dev]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'

jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: javascript-typescript
      - uses: github/codeql-action/analyze@v3
```

### TruffleHog (Secret scanning in PRs)

`.github/workflows/secrets.yml`:

```yaml
name: Secret Scan
on: [pull_request]
jobs:
  trufflehog:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD
```

---

## 2. security.txt

`public/.well-known/security.txt`:

```txt
Contact: mailto:security@yourdomain.com
Expires: 2027-12-31T23:59:59Z
Preferred-Languages: es, en
Canonical: https://yourdomain.com/.well-known/security.txt
```

---

## 3. DNS Security

### CAA records (only your CA issues certs)

```
yourdomain.com.    IN CAA 0 issue "letsencrypt.org"
yourdomain.com.    IN CAA 0 iodef "mailto:security@yourdomain.com"
```

### SPF + DKIM + DMARC

```
# SPF — who can send emails from your domain
yourdomain.com.    IN TXT "v=spf1 include:resend.com -all"

# DMARC — start monitoring, then enforce
_dmarc.yourdomain.com.    IN TXT "v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com"
# After 2 weeks: p=quarantine
# Final: p=reject
```

Verify: https://mxtoolbox.com/SuperTool.aspx

---

## 4. HSTS Preload

In middleware or `next.config.ts`:
```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

Submit to https://hstspreload.org/ when HTTPS is 100% stable.

---

## 5. SIEM Lite (Security Event Monitoring)

Hourly cron that reads `security_logs` and alerts on suspicious patterns:

```typescript
// app/api/cron/security-alerts/route.ts
export async function GET(req: Request) {
  // Verify cron authentication
  if (req.headers.get('authorization') !== `Bearer ${process.env.CRON_SECRET}`) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const supabase = createAdminClient()
  const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString()

  // Check brute force (>10 login failures from same IP)
  const { data: bruteForce } = await supabase
    .from('security_logs')
    .select('ip')
    .eq('type', 'login_failed')
    .gte('created_at', oneHourAgo)

  // Check privilege escalation attempts
  const { data: privesc } = await supabase
    .from('security_logs')
    .select('user_id')
    .eq('type', 'permission_denied')
    .gte('created_at', oneHourAgo)

  const alerts = []
  if ((bruteForce?.length ?? 0) > 10) alerts.push(`Brute force: ${bruteForce!.length} attempts`)
  if ((privesc?.length ?? 0) > 5) alerts.push(`Privesc: ${privesc!.length} attempts`)

  if (alerts.length) {
    await sendAlert({ subject: 'Security Alert', body: alerts.join('\n'), severity: 'high' })
  }

  return Response.json({ ok: true, alerts: alerts.length })
}
```

---

## 6. Encrypted Offsite Backup

`.github/workflows/backup.yml`:

```yaml
name: Daily Backup
on:
  schedule:
    - cron: '0 2 * * *'
  workflow_dispatch:

jobs:
  backup:
    runs-on: ubuntu-latest
    steps:
      - name: Dump database
        run: |
          pg_dump "${{ secrets.SUPABASE_DB_URL }}" \
            --no-acl --no-owner --clean --if-exists | gzip > backup.sql.gz

      - name: Encrypt
        run: |
          openssl enc -aes-256-gcm -salt -pbkdf2 -iter 100000 \
            -in backup.sql.gz -out backup.sql.gz.enc \
            -pass pass:"${{ secrets.BACKUP_ENCRYPTION_PASS }}"

      - name: Upload to offsite storage
        run: |
          # Backblaze B2, S3, or any offsite storage
          pip install b2
          b2 authorize-account ${{ secrets.B2_KEY_ID }} ${{ secrets.B2_APP_KEY }}
          b2 upload-file your-backup-bucket backup.sql.gz.enc \
            "$(date +%Y/%m/%d)-backup.sql.gz.enc"

      - name: Verify backup size
        run: |
          SIZE=$(stat -c %s backup.sql.gz.enc)
          if [ "$SIZE" -lt 1000 ]; then echo "Suspiciously small backup"; exit 1; fi
```

---

## New Project Checklist

Run for every new SaaS project:

```
- [ ] Dependabot activated in GitHub
- [ ] Secret scanning + push protection enabled
- [ ] CodeQL workflow in .github/workflows/
- [ ] TruffleHog workflow in .github/workflows/
- [ ] security.txt in public/.well-known/
- [ ] security@ email alias monitored
- [ ] CAA records in DNS
- [ ] SPF + DKIM + DMARC configured
- [ ] HSTS header in middleware
- [ ] SIEM lite cron (if security_logs table exists)
- [ ] Daily offsite backup cron
```
