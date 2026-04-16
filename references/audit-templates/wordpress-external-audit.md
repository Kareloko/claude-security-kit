# Template: WordPress Security Audit — Passive Reconnaissance

> Reusable template for auditing external WordPress sites.
> Auto-loaded by `saas-security-audit --deep` when WordPress stack is detected.
> All findings reference public OWASP/CWE documentation and known WordPress security advisories.
>
> **How to use:** replace all `{PLACEHOLDERS}`, verify each finding with the provided commands, delete sections that don't apply.

---

# WordPress Security Assessment — {DOMAIN}

**Date:** {YYYY-MM-DD}
**Auditor:** {AUDITOR_NAME}
**Contact:** {AUDITOR_EMAIL}
**Scope:** External passive reconnaissance (no active exploitation)
**Methodology:** OWASP Testing Guide v4.2 + PTES (Penetration Testing Execution Standard)
**Classification:** Confidential — {CLIENT_NAME} only

---

## Executive Summary (for non-technical stakeholders)

We performed a security assessment of {DOMAIN} from an external attacker's perspective, without accessing internal systems or exploiting vulnerabilities. We examined what information is publicly visible and what attack vectors exist.

**Overall Risk Level:** {CRITICAL / HIGH / MODERATE / LOW}

**Key finding:** {one-sentence summary of the most impactful issue}

**Immediate actions required:** {N} items need attention today to prevent potential compromise.

---

## Target Information

| Property | Value |
|----------|-------|
| Domain | {DOMAIN} |
| IP Address | {IP from dig/nslookup} |
| CMS | WordPress {VERSION or "version hidden"} |
| Page Builder | {Elementor / Divi / Gutenberg / none detected} |
| Server | {Apache / Nginx / LiteSpeed / unknown} |
| Hosting | {provider if detectable, or "shared hosting probable"} |
| CDN/WAF | {Cloudflare / Sucuri / none detected} |
| SSL Certificate | {valid until DATE / expired / absent} |
| SSL Grade | {A+ / A / B / C / F — from ssllabs.com} |
| Registration Country | {country} |

---

## Methodology

### Tools Used
- `curl` — HTTP header and response analysis
- `dig` / `nslookup` — DNS reconnaissance
- `nmap` — port scanning (if in scope)
- Browser DevTools — client-side analysis
- SSL Labs (ssllabs.com) — TLS configuration
- SecurityHeaders.com — HTTP header analysis
- MXToolbox — DNS and email security

### Scope Boundaries
- External reconnaissance only (no authenticated testing)
- No active exploitation of discovered vulnerabilities
- No denial of service testing
- No social engineering
- Only {DOMAIN} and its subdomains (if agreed)

---

## Findings

### FINDING-01: WordPress XML-RPC Interface Enabled

| Property | Value |
|----------|-------|
| Severity | HIGH |
| CVSS 3.1 | 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H) |
| CWE | CWE-307 (Improper Restriction of Excessive Authentication Attempts) |
| Status | {CONFIRMED / PROBABLE / NOT APPLICABLE} |

**Description:** The XML-RPC interface (`/xmlrpc.php`) is enabled by default in WordPress. It allows remote procedure calls that attackers abuse for amplified brute force attacks (system.multicall sends hundreds of password guesses in a single HTTP request), pingback DDoS reflection, and server-side request forgery.

**Verification:**
```bash
curl -s -o /dev/null -w "%{http_code}" https://{DOMAIN}/xmlrpc.php
# 200 or 405 = active, 403 or 404 = blocked
```

**Impact:** An attacker can attempt thousands of login combinations per minute without triggering standard rate limits, potentially gaining administrative access to the site.

**Remediation:**
- Block via `.htaccess`: `<Files xmlrpc.php> Order Deny,Allow Deny from all </Files>`
- Or block at WAF/Cloudflare level (recommended)
- Or use security plugin (Wordfence/iThemes) to disable XML-RPC
- Only keep enabled if Jetpack or WordPress mobile app is actively used

---

### FINDING-02: User Enumeration via REST API

| Property | Value |
|----------|-------|
| Severity | MEDIUM |
| CVSS 3.1 | 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) |
| CWE | CWE-200 (Exposure of Sensitive Information) |
| Status | {CONFIRMED / PROBABLE / NOT APPLICABLE} |

**Description:** WordPress exposes user information through the REST API endpoint `/wp-json/wp/v2/users` by default. This reveals usernames, display names, and user slugs without authentication, giving attackers valid usernames for brute force or credential stuffing attacks.

**Verification:**
```bash
curl -s https://{DOMAIN}/wp-json/wp/v2/users | python3 -m json.tool
# Also check author enumeration:
curl -s -o /dev/null -w "%{http_code}" "https://{DOMAIN}/?author=1"
```

**Impact:** Attacker obtains valid admin usernames, reducing brute force from O(n*m) to O(m) (only needs to guess passwords, not usernames).

**Remediation:**
- Disable REST API for unauthenticated users via security plugin
- Or add to functions.php: `add_filter('rest_authentication_errors', function($result) { if (!is_user_logged_in()) { return new WP_Error('rest_forbidden', 'REST API restricted.', ['status' => 401]); } return $result; });`
- Block `/?author=N` enumeration via .htaccess rewrite rule

---

### FINDING-03: Default Login Page Exposed

| Property | Value |
|----------|-------|
| Severity | MEDIUM |
| CVSS 3.1 | 5.0 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N) |
| CWE | CWE-288 (Authentication Bypass Using an Alternate Path) |
| Status | {CONFIRMED / PROBABLE / NOT APPLICABLE} |

**Description:** The WordPress login page is accessible at the default path `/wp-login.php` and `/wp-admin/`. No custom URL, CAPTCHA, or IP restriction was detected. Combined with user enumeration, this creates a direct brute force target.

**Verification:**
```bash
curl -s -o /dev/null -w "%{http_code}" https://{DOMAIN}/wp-login.php
curl -s -o /dev/null -w "%{http_code}" https://{DOMAIN}/wp-admin/
```

**Impact:** Direct target for automated brute force and credential stuffing attacks. Default WordPress has no built-in rate limiting on login attempts.

**Remediation:**
- Change login URL with WPS Hide Login plugin
- Add CAPTCHA (reCAPTCHA v3 or Cloudflare Turnstile) to login form
- Implement 2FA with WordFence or WP 2FA plugin
- Limit login attempts (Limit Login Attempts Reloaded plugin)
- Consider IP allowlist for /wp-admin if only specific people need access

---

### FINDING-04: Contact Forms Without Bot Protection

| Property | Value |
|----------|-------|
| Severity | MEDIUM |
| CVSS 3.1 | 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N) |
| CWE | CWE-799 (Improper Control of Interaction Frequency) |
| Status | {CONFIRMED / PROBABLE / NOT APPLICABLE} |

**Description:** {N} contact form(s) detected on the site without visible CAPTCHA, honeypot, or other anti-automation protection. Forms collect {fields detected: name, email, phone, company, message, etc.}.

**Verification:**
```bash
# Inspect form HTML for captcha elements
curl -s https://{DOMAIN} | grep -iE "recaptcha|hcaptcha|captcha|honeypot|g-recaptcha|cf-turnstile"
```

**Impact:** Automated bots can submit spam at scale, inject malicious content, harvest email addresses via auto-responders, or abuse the form as an email relay.

**Remediation:**
- Add reCAPTCHA v3 (invisible, best UX) or Cloudflare Turnstile (privacy-friendly)
- Add honeypot field (hidden input that bots fill, humans don't)
- Implement server-side rate limiting on form submission endpoint

---

### FINDING-05: Missing HTTP Security Headers

| Property | Value |
|----------|-------|
| Severity | MEDIUM |
| CVSS 3.1 | 4.3-6.1 depending on missing header |
| CWE | CWE-693 (Protection Mechanism Failure) |
| Status | {CONFIRMED / PROBABLE / NOT APPLICABLE} |

**Description:** The server does not send standard security headers that protect against common web attacks.

**Verification:**
```bash
curl -I https://{DOMAIN} 2>/dev/null | grep -iE "strict-transport|x-frame|x-content-type|content-security|referrer-policy|permissions-policy|x-xss"
# Or use: https://securityheaders.com/?q={DOMAIN}
```

**Missing headers assessment:**

| Header | Status | Risk if Missing |
|--------|--------|-----------------|
| `Strict-Transport-Security` | {Present/Missing} | HTTPS downgrade attacks |
| `X-Frame-Options` | {Present/Missing} | Clickjacking |
| `X-Content-Type-Options` | {Present/Missing} | MIME type sniffing |
| `Content-Security-Policy` | {Present/Missing} | XSS, data injection |
| `Referrer-Policy` | {Present/Missing} | Information leakage |
| `Permissions-Policy` | {Present/Missing} | Unauthorized feature access |

**Remediation:** Add headers via `.htaccess` (Apache), `nginx.conf` (Nginx), or security plugin (Really Simple SSL Pro, Headers Security Advanced):

```apache
# .htaccess
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' https: data:;"
```

---

### FINDING-06: WordPress Version Disclosure

| Property | Value |
|----------|-------|
| Severity | LOW |
| CVSS 3.1 | 3.7 (AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N) |
| CWE | CWE-200 (Exposure of Sensitive Information) |
| Status | {CONFIRMED / PROBABLE / NOT APPLICABLE} |

**Description:** WordPress reveals its version number through the `<meta name="generator">` tag, RSS feed, CSS/JS query strings (`?ver=X.X.X`), and the readme.html file. Knowing the exact version allows attackers to search for specific CVEs.

**Verification:**
```bash
curl -s https://{DOMAIN} | grep -i "generator"
curl -s -o /dev/null -w "%{http_code}" https://{DOMAIN}/readme.html
curl -s https://{DOMAIN} | grep -oP 'ver=[\d\.]+'  | sort -u
```

**Remediation:**
- `remove_action('wp_head', 'wp_generator');` in functions.php
- Delete `/readme.html` and `/license.txt` from WordPress root
- Remove version query strings from enqueued scripts/styles

---

### FINDING-07: Plugin/Theme Version Exposure

| Property | Value |
|----------|-------|
| Severity | MEDIUM |
| CVSS 3.1 | 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) |
| CWE | CWE-200 (Exposure of Sensitive Information) |
| Status | {CONFIRMED / PROBABLE / NOT APPLICABLE} |

**Description:** Plugin and theme paths visible in page source reveal installed components and potentially their versions. Key plugins like page builders have historically had critical CVEs (Elementor Pro: CVE-2023-32243, CVE-2022-29455; Divi: multiple XSS).

**Verification:**
```bash
curl -s https://{DOMAIN} | grep -oP '/wp-content/plugins/[^/]+' | sort -u
curl -s https://{DOMAIN} | grep -oP '/wp-content/themes/[^/]+' | sort -u
```

**Detected plugins:**
- {plugin-1} — {known CVEs or "no critical CVEs in current version"}
- {plugin-2} — {assessment}

**Remediation:**
- Keep ALL plugins updated (enable auto-updates for minor versions)
- Remove unused/deactivated plugins entirely (not just deactivate)
- Check detected plugins against WPScan Vulnerability Database: https://wpscan.com/plugins

---

### FINDING-08: Directory Listing Potentially Enabled

| Property | Value |
|----------|-------|
| Severity | LOW |
| CVSS 3.1 | 3.7 (AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N) |
| CWE | CWE-548 (Exposure of Information Through Directory Listing) |
| Status | {CONFIRMED / PROBABLE / NOT APPLICABLE} |

**Description:** WordPress upload directories (`/wp-content/uploads/YYYY/MM/`) may expose directory listings, revealing uploaded files, internal dates, and content structure.

**Verification:**
```bash
curl -s https://{DOMAIN}/wp-content/uploads/ | grep -i "index of"
curl -s https://{DOMAIN}/wp-content/uploads/2025/ | grep -i "index of"
```

**Remediation:**
- Apache: `Options -Indexes` in `.htaccess`
- Nginx: remove `autoindex on;` or add `autoindex off;`
- Add empty `index.php` files in upload directories

---

### FINDING-09: No WAF Detected

| Property | Value |
|----------|-------|
| Severity | LOW |
| CVSS 3.1 | N/A (architectural recommendation) |
| CWE | CWE-693 (Protection Mechanism Failure) |
| Status | {CONFIRMED / NOT APPLICABLE} |

**Description:** No Web Application Firewall (WAF) or CDN proxy was detected protecting the site. The origin server IP appears directly exposed, making it vulnerable to direct attacks bypassing any future WAF configuration.

**Verification:**
```bash
curl -I https://{DOMAIN} | grep -iE "cf-ray|x-sucuri|server.*cloudflare|x-cdn|x-cache"
dig {DOMAIN} +short  # Direct IP = no proxy
```

**Remediation:**
- **Minimum:** Cloudflare Free plan (WAF + DDoS protection + CDN + SSL)
- **Better:** Cloudflare Pro ($20/month) for advanced WAF rules
- **Alternative:** Sucuri WAF ($199/year, WordPress-specialized)
- After setup: restrict origin server to only accept traffic from WAF IPs

---

### FINDING-10: No CDN for Static Assets

| Property | Value |
|----------|-------|
| Severity | INFO |
| CVSS 3.1 | N/A (performance + security recommendation) |
| Status | {CONFIRMED / NOT APPLICABLE} |

**Description:** Images and static assets are served directly from the origin server without CDN caching. This increases server load, latency for distant users, and exposes the origin to direct traffic.

**Verification:**
```bash
curl -I https://{DOMAIN}/wp-content/uploads/{KNOWN_IMAGE} | grep -iE "x-cache|cf-cache|age:|cdn"
```

**Remediation:** Cloudflare (free tier includes CDN), BunnyCDN ($1/TB), or WP Rocket + CDN combo.

---

### FINDING-11: Personal Data Collection Without Privacy Policy

| Property | Value |
|----------|-------|
| Severity | MEDIUM (legal risk) |
| CVSS 3.1 | N/A (legal/compliance finding) |
| CWE | N/A |
| Status | {CONFIRMED / NOT APPLICABLE} |

**Description:** Forms collect personal data ({fields: name, email, phone, company, etc.}) without visible link to privacy policy, cookie consent banner, or data processing consent checkbox.

**Legal exposure by jurisdiction:**

| Jurisdiction | Law | Requirement | Potential Fine |
|-------------|-----|-------------|----------------|
| Chile | Ley 19.628 (+ future framework) | Consent before collection | Varies |
| Peru | Ley 29733 | Explicit consent + privacy policy | Up to 100 UIT (~$130K) |
| Colombia | Ley 1581 | Prior authorization + privacy notice | Up to 2,000 SMLMV (~$500K) |
| Mexico | LFPDPPP | Privacy notice before collection | Up to $1.5M MXN |
| EU (if EU visitors) | GDPR | Explicit consent + DPO + privacy policy | Up to 4% annual revenue |

**Remediation:**
- Add privacy policy page linked from footer and forms
- Add consent checkbox on all forms: "I accept the privacy policy"
- Add cookie consent banner (CookieYes or Complianz plugin, both have free tier)
- Document data processing purposes and retention periods

---

### FINDING-12: SSL/TLS Configuration Assessment

| Property | Value |
|----------|-------|
| Severity | {CRITICAL if expired / LOW if minor issues / INFO if good} |
| CVSS 3.1 | Varies |
| CWE | CWE-295 (Improper Certificate Validation) |
| Status | {CONFIRMED} |

**Verification:**
```bash
# Quick check
curl -vI https://{DOMAIN} 2>&1 | grep -E "expire|subject|issuer"
# Full analysis
# Visit: https://www.ssllabs.com/ssltest/analyze.html?d={DOMAIN}
```

**Assessment:**

| Check | Status |
|-------|--------|
| Certificate valid | {Yes/No} |
| Expires | {DATE} |
| Issuer | {Let's Encrypt / Comodo / etc.} |
| TLS 1.2+ only | {Yes/No — TLS 1.0/1.1 should be disabled} |
| HSTS enabled | {Yes/No} |
| SSL Labs grade | {A+/A/B/C/F} |

---

### FINDING-13: Email Security (SPF/DKIM/DMARC)

| Property | Value |
|----------|-------|
| Severity | MEDIUM |
| CVSS 3.1 | N/A (phishing prevention) |
| CWE | CWE-290 (Authentication Bypass by Spoofing) |
| Status | {CONFIRMED / NOT APPLICABLE} |

**Description:** Without SPF, DKIM, and DMARC records, anyone can send emails appearing to come from {DOMAIN}, enabling convincing phishing attacks against the organization's clients.

**Verification:**
```bash
dig {DOMAIN} TXT +short | grep "v=spf1"
dig _dmarc.{DOMAIN} TXT +short
dig default._domainkey.{DOMAIN} TXT +short
# Or use: https://mxtoolbox.com/SuperTool.aspx?action=mx:{DOMAIN}
```

| Record | Status |
|--------|--------|
| SPF | {Present: "v=spf1..." / Missing} |
| DKIM | {Present / Missing / Cannot verify externally} |
| DMARC | {Present with p=none / p=quarantine / p=reject / Missing} |

**Remediation:**
- Add SPF: `v=spf1 include:{EMAIL_PROVIDER} -all`
- Configure DKIM through email provider
- Add DMARC: start with `v=DMARC1; p=none; rua=mailto:dmarc@{DOMAIN}`, escalate to `p=reject` after monitoring

---

### FINDING-14: Public Source Code Repository

| Property | Value |
|----------|-------|
| Severity | {CRITICAL if contains secrets / HIGH if contains backend code / MEDIUM if frontend only} |
| CVSS 3.1 | Up to 9.8 if credentials found |
| CWE | CWE-540 (Inclusion of Sensitive Information in Source Code) |
| Status | {CONFIRMED / NOT APPLICABLE} |

**Description:** A public repository related to the project was found at {REPO_URL}. If it contains API keys, database credentials, backend logic, or internal documentation, this represents a critical information disclosure.

**Verification:**
```bash
# Search GitHub for related repos
# github.com/search?q={DOMAIN_OR_ORG_NAME}
# Check for secrets in commit history:
# trufflehog git https://{REPO_URL} --only-verified
```

**Remediation:**
- Audit repository immediately for exposed secrets
- If secrets found: rotate ALL exposed credentials before making repo private
- Use BFG Repo Cleaner to remove secrets from git history
- Make repository private or delete if not needed publicly
- Enable GitHub Secret Scanning on the repository

---

### FINDING-15: Outdated PHP Version (if detectable)

| Property | Value |
|----------|-------|
| Severity | {HIGH if PHP < 8.1 / MEDIUM if 8.1 / LOW if 8.2+} |
| CVSS 3.1 | Varies by PHP version CVEs |
| CWE | CWE-1104 (Use of Unmaintained Third Party Components) |
| Status | {CONFIRMED / UNDETECTABLE / NOT APPLICABLE} |

**Verification:**
```bash
curl -I https://{DOMAIN} | grep -i "x-powered-by"
# If header is hidden (good practice), PHP version may not be detectable externally
```

**Active PHP support status:**
- PHP 8.3+ — actively supported (recommended)
- PHP 8.2 — security fixes until Dec 2025
- PHP 8.1 — end of life Dec 2025
- PHP 8.0 and below — end of life, no security patches

---

## Risk Summary

| Severity | Count | Findings |
|----------|-------|----------|
| CRITICAL | {N} | {IDs and short descriptions} |
| HIGH | {N} | {IDs} |
| MEDIUM | {N} | {IDs} |
| LOW | {N} | {IDs} |
| INFO | {N} | {IDs} |

**Total findings:** {N}

---

## Prioritized Action Plan

### Immediate (today — estimated {X} hours)
{List critical and high findings that can be fixed quickly}

### This Week (estimated {X} hours)
{List medium findings and quick wins}

### This Month
{List remaining findings, plugin audits, monitoring setup}

### Ongoing
- WordPress core auto-updates enabled
- Plugin auto-updates for minor/patch versions
- Monthly manual review of security plugin dashboard
- Quarterly review of installed plugins (remove unused)
- Annual external security assessment

---

## Auditor Verification Checklist

Complete technical checklist for auditor to run against any WordPress target:

```bash
# 1. Stack detection
curl -I https://{DOMAIN}
curl -s https://{DOMAIN} | grep -iE "wp-content|wp-includes|generator"

# 2. WordPress version
curl -s https://{DOMAIN} | grep -oP 'content="WordPress [\d\.]+"'
curl -s -o /dev/null -w "%{http_code}" https://{DOMAIN}/readme.html

# 3. REST API user enumeration
curl -s https://{DOMAIN}/wp-json/wp/v2/users
curl -s -o /dev/null -w "%{http_code}" "https://{DOMAIN}/?author=1"

# 4. XML-RPC
curl -s -o /dev/null -w "%{http_code}" https://{DOMAIN}/xmlrpc.php

# 5. Login page
curl -s -o /dev/null -w "%{http_code}" https://{DOMAIN}/wp-login.php

# 6. Directory listing
curl -s https://{DOMAIN}/wp-content/uploads/ | grep -i "index of"

# 7. Security headers
curl -I https://{DOMAIN} | grep -iE "strict-transport|x-frame|x-content-type|content-security|referrer|permissions"

# 8. WAF/CDN detection
curl -I https://{DOMAIN} | grep -iE "cf-ray|x-sucuri|server.*cloudflare|x-cdn"

# 9. SSL grade
echo "Check: https://www.ssllabs.com/ssltest/analyze.html?d={DOMAIN}"

# 10. Email security
dig {DOMAIN} TXT +short
dig _dmarc.{DOMAIN} TXT +short

# 11. Plugin enumeration
curl -s https://{DOMAIN} | grep -oP '/wp-content/plugins/[^/]+' | sort -u
curl -s https://{DOMAIN} | grep -oP '/wp-content/themes/[^/]+' | sort -u

# 12. CAPTCHA on forms
curl -s https://{DOMAIN} | grep -iE "recaptcha|hcaptcha|captcha|turnstile"

# 13. PHP version (if exposed)
curl -I https://{DOMAIN} | grep -i "x-powered-by"

# 14. OSINT — public repositories
echo "Search: github.com/search?q={DOMAIN_OR_ORG}"

# 15. Subdomain enumeration (if in scope)
# subfinder -d {DOMAIN} -all
```

---

## Disclaimer

This assessment was conducted from an external perspective using passive reconnaissance techniques only. No systems were accessed, modified, or exploited. Findings are based on publicly observable information. Some vulnerabilities marked as "PROBABLE" require authenticated access to confirm definitively.

This report is provided for security improvement purposes. The auditor assumes no liability for actions taken based on these findings. All remediation should be tested in a staging environment before applying to production.

---

**Report generated on {YYYY-MM-DD} by {AUDITOR_NAME}**
**Methodology: OWASP Testing Guide v4.2 | PTES**
