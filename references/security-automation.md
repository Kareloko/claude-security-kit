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
      - uses: trufflesecurity/trufflehog@v3.88.0  # pin to specific version, not @main
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
Policy: https://yourdomain.com/security/policy
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

**Ramp-up recomendado:** empezar con `max-age=300` (5 min) para probar, luego subir a `max-age=31536000` (1 año), y finalmente a 2 años + preload. Si HTTPS falla con max-age alto, quedas bloqueado ese tiempo.

Submit to https://hstspreload.org/ cuando HTTPS sea 100% estable y max-age sea >= 1 año.

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

  // Check brute force: >10 login failures from SAME IP in 1 hour
  const { data: bruteForce } = await supabase.rpc('detect_brute_force_ips', {
    since: oneHourAgo,
    threshold: 10,
  })
  // SQL: SELECT ip, COUNT(*) as attempts FROM security_logs
  //   WHERE type = 'login_failed' AND created_at > $1
  //   GROUP BY ip HAVING COUNT(*) > $2

  // Check privilege escalation: >5 permission_denied from same user
  const { data: privesc } = await supabase.rpc('detect_privesc_attempts', {
    since: oneHourAgo,
    threshold: 5,
  })
  // SQL: SELECT user_id, COUNT(*) as attempts FROM security_logs
  //   WHERE type = 'permission_denied' AND created_at > $1
  //   GROUP BY user_id HAVING COUNT(*) > $2

  const alerts = []
  if (bruteForce?.length) alerts.push(`Brute force: ${bruteForce.length} IPs with 10+ failures`)
  if (privesc?.length) alerts.push(`Privesc: ${privesc.length} users with 5+ denials`)

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
          # NOTE: openssl enc does NOT support GCM mode. Use CBC or gpg instead.
          gpg --batch --yes --symmetric --cipher-algo AES256 \
            --passphrase "${{ secrets.BACKUP_ENCRYPTION_PASS }}" \
            --output backup.sql.gz.gpg backup.sql.gz
          # Alternative if gpg unavailable:
          # openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
          #   -in backup.sql.gz -out backup.sql.gz.enc \
          #   -pass pass:"${{ secrets.BACKUP_ENCRYPTION_PASS }}"

      - name: Upload to offsite storage
        run: |
          # Backblaze B2 CLI v4+ syntax
          pip install b2sdk
          b2 account authorize ${{ secrets.B2_KEY_ID }} ${{ secrets.B2_APP_KEY }}
          b2 file upload your-backup-bucket backup.sql.gz.gpg \
            "$(date +%Y/%m/%d)-backup.sql.gz.gpg"

      - name: Verify backup integrity
        run: |
          SIZE=$(stat -c %s backup.sql.gz.gpg)
          if [ "$SIZE" -lt 1000 ]; then echo "Suspiciously small backup"; exit 1; fi
          # Verify decryption works (integrity check)
          gpg --batch --yes --passphrase "${{ secrets.BACKUP_ENCRYPTION_PASS }}" \
            --decrypt backup.sql.gz.gpg | gunzip | pg_restore --list > /dev/null 2>&1 \
            && echo "Backup integrity OK" || echo "WARNING: backup may be corrupt"
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
