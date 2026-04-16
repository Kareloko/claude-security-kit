# Offensive Security — Ethical Hacking & Audit Playbook

> Load when `saas-security-audit --deep` is invoked. For auditing systems with explicit written permission, bug bounty programs, CTF training, or hardening your own SaaS.

**Fundamental principle:** ethical hacking = attacking with explicit permission to find flaws before the bad guys do. Without written permission = crime. With permission = profession.

---

## Standard Audit Flow

```
1. Scope agreement signed (what to attack, what NOT, dates, deliverables)
2. Passive reconnaissance (OSINT, whois, dig, Subfinder)
3. Active reconnaissance (nmap, ffuf, gobuster)
4. Web analysis (Burp/ZAP, nikto, sqlmap)
5. Controlled exploitation (only enough to prove impact)
6. Documentation (screenshots, reproducible steps)
7. Report with severity + suggested fix
8. Retest after fix
```

---

## Base Toolkit

### Burp Suite (interception proxy)

Industry standard. Intercepts, modifies and replays HTTP/HTTPS requests.

**Minimum tests against your apps:**
1. Change `user_id`/IDs in URLs -> does it return other user's data? (IDOR)
2. Remove `Authorization` header -> does it still work? (broken auth)
3. Manipulate JWT payload -> does it accept without verifying signature?
4. Send other users' IDs in body -> does RLS block it?
5. Upload with disguised extension (.php renamed to .jpg)

### Kali Linux — essential toolkit

```bash
# RECONNAISSANCE
nmap -sV -sC -O target.com
nmap -p- --min-rate 5000 target.com
whois example.com
dig example.com ANY
theHarvester -d target.com -b google,bing
subfinder -d target.com -all
ffuf -u https://target.com/FUZZ -w common.txt

# WEB ANALYSIS
nikto -h https://target.com
sqlmap -u "target.com/api/x?id=1" --dbs
gobuster dir -u target.com -w medium.txt -x php,js,json

# NETWORK
tshark -i eth0 -w capture.pcap
tcpdump -i eth0 -n port 443
```

### OWASP ZAP (open source alternative to Burp)

```bash
# Automated scan with Docker
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://your-app.com

# GitHub Actions integration (pin to recent stable version)
- name: ZAP Scan
  uses: zaproxy/action-baseline@v0.13.0
  with:
    target: 'https://your-app.vercel.app'
```

---

## Bug Bounty

**Platforms:**
- HackerOne (hackerone.com) — largest
- Bugcrowd (bugcrowd.com)
- Intigriti (intigriti.com) — Europe
- Immunefi (immunefi.com) — blockchain/DeFi

**Typical payment ranges:**
- Low: $50-$500
- Medium: $500-$3,000
- High: $3,000-$15,000
- Critical: $15,000-$100,000+

---

## Professional Report Template

```markdown
## Title
[Vulnerability type] in [endpoint] allows [impact]

## Severity
[Critical | High | Medium | Low | Info] — with justification

## Description
[What vulnerability, what it allows, why exploitable]

## Steps to Reproduce
1. Authenticate as user A
2. Get resource X with known ID
3. Authenticate as user B
4. GET /api/X/{id_from_A}
5. Response returns A's data

## Evidence
[Screenshots + curls + responses]

## Impact
[What data exposed, how many users affected, what compliance violated]

## Suggested Fix
[Concrete technical solution: code, RLS policy, header, etc.]

## References
[CWE, OWASP, related CVEs]
```

---

## Digital Forensics (post-incident)

When something already happened in production and you need to understand what.

```bash
# Cloud-native forensics (most SaaS incidents happen here)
# Vercel: Dashboard > Logs > Export, or:
vercel logs https://deployment-url.vercel.app > incident.log
# Supabase: Dashboard > Logs > API/Auth/Postgres
# Cloudflare: Dashboard > Security > Events

# Analyze log patterns
grep "401\|403\|429" incident.log | sort | uniq -c | sort -rn | head -20

# Forensic disk copy (only for VPS/bare-metal, not cloud SaaS)
dd if=/dev/sda of=disk.img bs=4M status=progress
sha256sum disk.img > disk.img.sha256

# RAM analysis — Volatility 3 (current version, v2 is legacy)
vol -f memory.dmp windows.info
vol -f memory.dmp windows.pslist
vol -f memory.dmp windows.netscan
# Legacy Volatility 2 (if v3 unavailable):
# volatility -f memory.dmp imageinfo
# volatility -f memory.dmp --profile=Win10x64 pslist
```

---

## Social Engineering & Phishing

90% of breaches start here. They don't break code — they break people.

**Types:** Phishing, Spear phishing, Vishing (phone), Smishing (SMS), Pretexting, OAuth Consent Phishing.

**Defense:**
1. MFA on ALL critical accounts
2. Verify real domain before clicking
3. Never enter credentials from email link
4. Review connected OAuth apps quarterly

---

## Legal Practice Platforms

- **TryHackMe** (tryhackme.com) — guided, ideal for beginners
- **HackTheBox** (hackthebox.com) — real challenge, vulnerable machines
- **OWASP WebGoat** — intentional vulnerabilities for learning
- **DVWA** — local, no legal risk: `docker run --rm -it -p 80:80 vulnerables/web-dvwa`
- **PortSwigger Web Security Academy** — free, by Burp creators

---

## Certifications

- **CEH** (Certified Ethical Hacker) — basic, theoretical
- **OSCP** (Offensive Security) — 100% practical, most respected
- **CISSP** — management, more executive
- **eJPT / eCPPTv3** (INE Security, formerly eLearnSecurity) — practical, accessible prices

---

## Anti-Patterns

- Attacking outside agreed scope -> contract breach, legal risk
- Testing destructive exploits (DoS, data deletion) without explicit authorization
- Reporting without reproducible steps -> client can't validate
- Inflating severity to charge more -> reputation loss
- Not retesting after fix -> don't close the loop
- Sharing client data outside the report -> NDA breach
