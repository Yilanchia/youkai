# Security policy

youkai is a tool for **authorised** security testing. It is built so that
"authorised" is enforced by construction, not by good intentions.

## What youkai is for, and what it refuses

- It sends requests **only** to targets in an engagement's scope passport. No
  scope, no request; no code path sends a request without the guard seeing it.
- The autonomous loop is **read-only**. Anything that touches state (active
  probing, login, seeding, registration) stops and waits for a human approval,
  one step at a time, plus a signed high-authorisation record.
- The exploitation tier is **not in this repository**. There is no build tag, no
  flag, and no branch that adds it.

Using youkai against systems you do not own or have written permission to test is
a violation of its license and of the law in most jurisdictions.

## Reporting a vulnerability in youkai

Please report **privately**, not in a public issue:

- Open a [private security advisory](https://docs.github.com/en/code-security/security-advisories)
  on the repository, or
- contact the maintainers directly and ask for a secure channel.

Include the version (`youkai -version` or the commit), a minimal reproduction, and
what invariant you believe is broken. We aim to acknowledge within 72 hours.

### What counts as a youkai vulnerability

These are the invariants a report is judged against:

| Invariant | What breaking it looks like |
|---|---|
| **One egress path** | A request leaves the machine without `discipline.Guard` authorising it and writing an audit row (a second HTTP client, a raw socket, a subprocess that dials out). |
| **Scope enforcement** | An out-of-scope host or a redirect hop reaches the target; a hostname resolves into private space behind the passport's back. |
| **Audit completeness / integrity** | A sent request without an `audit_log` row, or a way to modify/delete audit rows (the DB trigger is the guard here). |
| **Credential containment** | A cookie, password, API key or session value appears in the ledger, the audit detail, a report, a snapshot, a screenshot sidecar, or a log line. |
| **Tier wall** | A tier-2 capability runs without an operator approval (single-use, fingerprint-bound) **and** a valid high-auth record; or tier 3 becomes reachable from this build. |
| **Report integrity** | A report/snapshot not derivable from the ledger; a candidate presented as verified; a disclosure containing a non-verified finding. |
| **Database guardrails** | `audit_log` / `report_snapshots` accept UPDATE/DELETE; `findings` can be verified without an operator verdict; `intents.approved` can be set without an approval row. |

### What is not a youkai vulnerability

- A vulnerability youkai **finds** in a target you authorised it to test. Report
  that to the target's owner.
- "It would be more powerful if you added exploitation / brute force / credential
  stuffing." Those are design refusals, not bugs.
- A model (LLM) proposing something dangerous. Proposals are inert: they are
  classified by `gate`, parked at the human workbench, and archived. A proposal
  is not an execution.
- Requiring operator setup (a token, a high-auth key, a session passphrase). Those
  are deliberate preconditions.

## Supported versions

The project is pre-1.0; only the tip of `main` receives security fixes.
