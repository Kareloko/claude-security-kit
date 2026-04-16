---
name: saas-security-review
description: "Daily review orchestrator for SaaS apps. Runs in sequence: simplify (code quality) -> saas-security-audit (security rules) -> nexusai-quality-security (universal OWASP check). Optionally invokes code-reviewer agent for second opinion. Use when you say 'security review', 'review my feature', 'daily review', 'review before merge', 'check quality and security'. For full pre-launch review use nexusai-quality-report instead."
---

# SaaS Security Review — Daily Orchestrator

> **Role:** Quality coordinator for daily development work. Ensures every finished feature passes through the quality + security funnel before merging.
> **Philosophy:** Quick but relentless review. One blocker = no merge. Give concrete fixes, not just problems.

## When to use

**YES:**
- Finished a feature, about to merge to `dev` or `main`
- Significant changes in auth, RLS, Server Actions, API routes
- Want a quick full review without running pre-launch
- Before asking for human PR review

**NO (use another skill):**
- Pre-launch to production -> `nexusai-quality-report`
- Only security-specific check -> `saas-security-audit`
- Only security with offensive tools -> `saas-security-audit --deep`
- Only spelling in staged files -> `corrector`

## Difference vs `nexusai-quality-report`

| Aspect | `saas-security-review` | `nexusai-quality-report` |
|--------|----------------------|--------------------------|
| When | Daily, feature done | Pre-launch, before production |
| Weight | Lightweight, fast | Heavy, exhaustive |
| Skills | 3 (quality + double security) | 6 (infra, security, perf, qa, product, load) |
| Duration | Minutes | Tens of minutes |
| Load testing | No | Yes |

---

## EXECUTION PROTOCOL

### Order (DO NOT ALTER)

```
1. simplify                  -> Is the code clean, reusable, efficient?
2. saas-security-audit       -> Does it comply with production security rules?
3. nexusai-quality-security  -> Universal second opinion (double safety net)
4. [Optional] code-reviewer  -> If ambiguous blockers need judgment call
```

**Why this order?**
- **Simplify first** -> clean code before auditing. Fix duplication/inefficiency, then audit on clean base.
- **Security audit second** -> validates specific production rules (the ones universal scanners miss).
- **Universal security third** -> validates standard OWASP checks. Double safety net.
- **Code-reviewer optional** -> only if phases 1-3 found something ambiguous needing judgment.

**Note on `corrector`:** NOT invoked here. Corrector works on `git staged` files, which conflicts with the review cycle (you're not committing yet). Corrector triggers separately via pre-commit hook.

---

### Short-circuit rule

If `simplify` reports **critical** architecture problems (massive dead code, severe duplication, major tech debt):

```
PIPELINE PAUSED

Simplify detected structural problems requiring human decision.
Fix first or justify continuing. Then re-run saas-security-review.

Problems detected:
[list]
```

If user confirms "continue anyway", proceed with remaining phases marking it as warning in final report.

---

### Phase execution

For each skill:

1. **Invoke the skill** via Skill tool
2. **Wait for complete result**
3. **Capture findings** with classification:
   - OK
   - WARNING (doesn't block merge)
   - BLOCKER (don't merge until fixed)
   - AMBIGUOUS (needs second opinion -> invoke code-reviewer)
4. **Continue to next skill** (don't stop for warnings, only for blockers if short-circuit applies)

---

### When to invoke code-reviewer (agent)

Only if **at least one** of these conditions is met after all 3 phases:

- 2+ findings marked as AMBIGUOUS
- The two security skills (saas-security-audit and nexusai-quality-security) **disagree** (one says OK, other says blocker)
- User explicitly requests it with `--with-reviewer`

---

## FINAL REPORT FORMAT

```markdown
# SaaS Security Review — Daily Report
## Project: [name]
## Branch: [current branch]
## Date: YYYY-MM-DD HH:MM
## Verdict: [READY TO MERGE | MERGE WITH WARNINGS | DO NOT MERGE]

---

## Executive Summary

| Phase | Status | Blockers | Warnings | OK |
|-------|--------|----------|----------|-----|
| 1. simplify | OK/WARN/BLOCK | N | N | N |
| 2. saas-security-audit | OK/WARN/BLOCK | N | N | N |
| 3. nexusai-quality-security | OK/WARN/BLOCK | N | N | N |
| 4. code-reviewer (optional) | OK/WARN/-- | N | N | -- |

**TOTAL: N blockers, N warnings**

---

## BLOCKERS (fix before merge)

### 1. [Descriptive title]
- **Phase:** saas-security-audit / nexusai-quality-security / simplify
- **File:** src/app/api/x/route.ts:42
- **CIA Pillar:** Confidentiality / Integrity / Availability
- **Problem:** [clear description]
- **Fix:**
  ```typescript
  [correct code]
  ```

---

## WARNINGS (fix this sprint)
[...]

## Passed OK (summary)
- [x] Simplify: clean code, no significant duplication
- [x] Security audit: all production rules verified
- [x] Universal security: OWASP Top 10 covered

---

## Suggested Decision

[One of 3:]

MERGE CONFIDENTLY. All checks passed.

MERGE but create issues for the N warnings. None block, but they stay on the tech debt list.

DO NOT MERGE. N blockers require prior fix. Suggested fix order:
1. [Blocker 1] (highest impact)
2. [Blocker 2]
After fixing, re-run saas-security-review to confirm.

---

## Recommended Next Step

[If going to production:] Run nexusai-quality-report for full pre-launch review.
[If not:] Proceed with commit/merge. The corrector hook will run automatically on pre-commit.
```

---

## ANTI-PATTERNS

- **Don't run skills in parallel** -> they depend on order (simplify cleans code before auditing)
- **Don't skip phases** for urgency -> one omission = production bug
- **Don't rewrite findings** -> report what each skill said, without reinterpreting
- **Don't declare "all OK" if a skill marked blocker** -> blocker overrides average
- **Don't invoke code-reviewer always** -> only for the 3 defined cases
- **Don't run nexusai-quality-report at the end automatically** -> it's a human decision (pre-launch != daily merge)
- **Don't modify code directly** -> report, user decides what to fix
