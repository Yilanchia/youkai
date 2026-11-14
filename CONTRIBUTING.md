# Contributing

youkai is a safety-first tool: the discipline is the product, the scanning is the
demonstration. Contributions are judged against that order.

## Build and test

```bash
# PostgreSQL is required for the ledger tests. Any instance works; CI uses a
# throwaway container, and scripts/acceptance-v02.ps1 manages its own.
export YOUKAI_TEST_DSN="postgres://youkai:youkai_dev_pw@127.0.0.1:55432/youkai_test?sslmode=disable"

go build ./...
go vet ./...
gofmt -l .            # must print nothing
go test ./... -count=1
```

End-to-end (starts its own database, lab target, and server):

```bash
pwsh scripts/acceptance-v02.ps1      # Windows
```

Two CI jobs must be green before review: `ci` (build/vet/test/fmt) and
`invariants` (the security predicates below).

## Adding a capability — the non-negotiables

1. **Every request goes through `discipline.Guard`.** A capability receives a
   `*disciplized.Guard` (via `web.Env` / `binary.Env`) and calls
   `guard.Do(ctx, discipline.Request{...})`. Nothing else may dial out.
   `TestNoEgressOutsideTheGuard` fails the build otherwise.
2. **It must be classified.** Add the capability to `internal/gate/classify.go`.
   Read-only work is tier 1; anything that sends a payload, writes, logs in, seeds
   objects, or registers an account is tier 2. There is no "autonomous tier 2".
3. **Tier 2 needs the full door**: `requires_approval`, the scope switch checked
   before the approval is consumed, and the high-auth record verified. If your
   capability needs a new passport switch, add it to `discipline.Scope` and to
   `requiredScopeSwitch`.
4. **Evidence must be citable.** Every fact/finding carries a `request_id` that
   resolves to an `audit_log` row. Findings start as `candidate`; only an operator
   verdict promotes them.
5. **No secrets in output.** Not in facts, findings, traces, reports, snapshots,
   screenshots or logs. Values you must not emit: cookies, session headers,
   passwords, API keys, tokens, response bodies.

## What is not accepted

- Any second request path (an `http.Client` outside `internal/discipline`, a raw
  socket, shelling out to `curl`, a browser that opens its own connections without
  the Fetch gate).
- Anything that runs a tier-2 capability without a human (batch approval, "approve
  all", an LLM that self-approves, an automation that pre-signs high-auth records).
- Tier-3 code, build tags, or "just for testing" exploitation helpers.
- Committing real engagement data: `.youkai/`, `.pgsql/`, `bench/results/` are
  git-ignored except the placeholder files.

## Style

- Comments explain *why*, and where possible name the failure the code prevents.
  A comment that restates the code is noise; a comment that records a defect found
  in the field is load-bearing.
- Errors say what to do next ("set `YOUKAI_SESSION_KEY` or use `key_from_env`"), not
  just what failed.
- Tests: prove the invariant, not the implementation. Prefer "an out-of-scope fetch
  is blocked and audited" over "the handler returns 403".

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md). Do not open a public issue for an invariant break.

## License

MIT. By contributing you agree your contribution is licensed under it. Ported
material must keep its copyright notice — see [NOTICE](NOTICE).
