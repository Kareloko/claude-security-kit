# Template: WordPress External Security Audit (Passive Recon)

> Template for auditing external WordPress sites (clients under contract).
> Load when `saas-security-audit --deep` detects WordPress stack.

**Usage:** Copy this structure, replace `{DOMAIN}`, complete with real verified findings.

---

# Security Audit — {DOMAIN}
**Date:** {YYYY-MM-DD}
**Scope:** Passive reconnaissance (HTTP response analysis, HTML, exposed assets)
**Auditor:** {YOUR_NAME}

---

## Detected Stack

- **CMS:** WordPress (self-hosted / managed)
- **Page Builder:** {Elementor Pro / Divi / Gutenberg / other}
- **Hosting:** {detected or "shared hosting probable"}
- **CDN/WAF:** {Cloudflare / Sucuri / none detected}
- **SSL:** {Active / Absent / Expired}

---

## Critical Vulnerabilities

### 1. Contact forms without anti-spam
- **Evidence:** {N} forms without reCAPTCHA/hCaptcha/honeypot
- **Risk:** Mass spam, data injection, endpoint abuse
- **CVSS:** 5.3 (Medium)
- **Fix:** reCAPTCHA v3 or Cloudflare Turnstile

### 2. User enumeration via REST API
- **Evidence:** `/wp-json/wp/v2/users` accessible without auth
- **CVSS:** 5.3 (Medium)
- **Fix:** Block REST API for unauthenticated users

### 3. XML-RPC active
- **Evidence:** `/xmlrpc.php` responds
- **Risk:** Amplified brute force (multicall), DDoS pingback, SSRF
- **CVSS:** 7.5 (High)
- **Fix:** Block via `.htaccess` or WAF

### 4. wp-login.php exposed (default URL)
- **CVSS:** 5.0 (Medium)
- **Fix:** WPS Hide Login + 2FA + Limit Login Attempts

---

## Medium Vulnerabilities

### 5. Page Builder attack surface
### 6. Directory listing / exposed paths
### 7. Missing HTTP security headers
### 8. WordPress version exposed

---

## Low / Recommendations

### 9. No WAF detected
### 10. No CDN
### 11. Forms collecting PII without privacy policy
### 12. Public GitHub repository found

---

## Risk Summary

| Severity | Count | Items |
|----------|-------|-------|
| Critical/High | {N} | {short list} |
| Medium | {N} | {short list} |
| Low/Info | {N} | {short list} |

---

## Priority Action Plan

**Today:** {critical actions}
**This week:** {Cloudflare, headers, hide WP version, 2FA}
**This month:** {audit all plugins, privacy policy, disable REST API}
**Ongoing:** Wordfence/Sucuri monitoring, auto backups, auto updates

---

## Auditor Technical Checklist

```bash
curl -I https://{DOMAIN}
curl -s https://{DOMAIN} | grep -i "wp-content\|generator"
curl -s https://{DOMAIN}/wp-json/wp/v2/users
curl -I https://{DOMAIN}/xmlrpc.php
curl -I https://{DOMAIN}/wp-login.php
curl -s https://{DOMAIN}/wp-content/uploads/ | grep -i "index of"
curl -I https://{DOMAIN} | grep -iE "strict-transport|x-frame|content-security"
curl -I https://{DOMAIN} | grep -iE "cf-ray|x-sucuri|cloudflare"
dig {DOMAIN} ANY
dig {DOMAIN} TXT
```
