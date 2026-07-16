# ADR-0005: Build for OpenSSF Scorecard/Supply-Chain Trust From Day One, Not Retroactively

**Status:** Accepted
**Date:** 2026-07-16

## Context

Because GhostHound's deliverable is explicitly *foundational libraries other tooling will
depend on* (ADR-0001), supply-chain trust is not a bolt-on concern — it is close to the product
itself. OpenSSF Scorecard specifically rewards signals that accumulate over the project's history
and cannot be backfilled cheaply: CI running on every PR since the first commit, branch
protection age, commit-signing history, pinned-Action history. Retrofitting these after a project
has grown costs materially more than starting with them, and the historical checks stay
permanently weaker than if they'd been present from commit #1.

`skewrun` (the author's prior project, same house style target) already has this exact
configuration validated in practice — Scorecard badge, OpenSSF Best Practices badge, `deny.toml`,
signed commits, CI on PRs — so the marginal cost of replicating it here is low: it's config reuse,
not new design work.

## Decision

Split the supply-chain surface into what must exist at scaffold time versus what can only be
meaningful once the project has releases:

**Do now, at repo scaffold (structural / history-sensitive — cannot be backfilled without cost):**
- `deny.toml` + `cargo deny check` in CI (licenses, advisories, bans, sources).
- `cargo audit` / `osv-scanner` job in CI.
- CI (`fmt --check`, `clippy -D warnings`, `test`) running on every PR starting at commit #1 —
  Scorecard's *CI-Tests* check is a history metric, not a point-in-time one.
- GitHub Actions **pinned by commit SHA**, not floating tags — *Pinned-Dependencies*,
  *Dangerous-Workflow*.
- Least-privilege `permissions:` block in every workflow — *Token-Permissions*.
- Branch protection + required status checks on `main` from the start — *Branch-Protection*
  (also a history metric).
- **Signed commits** from the first commit.
- `SECURITY.md` (*Security-Policy*); Dependabot/Renovate configured for both crate deps and
  pinned Actions.
- `#![forbid(unsafe_code)]` on `bloodhound-opengraph` and `ad-secdesc` (from-scratch parser per
  ADR-0003) where feasible — a strong, cheap trust signal for libraries specifically.
- The **OpenSSF Scorecard GitHub Action** itself, running from early on, with the resulting badge
  in the README (mirroring `skewrun`'s README).
- `fuzz/` targets scaffolded early for `ad-secdesc` (and any wire-parsing in `ad-tombstone`) for
  panic-safety — depth of corpus grows later, but the harness and CI wiring start now.

**Defer until the project has actual releases/maturity (only meaningful at that point):**
- OpenSSF **Best Practices** badge submission (start at "passing"; pursue silver/gold once mature).
- **Signed releases** / SLSA provenance / GitHub artifact attestation — requires a release
  pipeline to exist first.
- Fuzz **corpus** maturity/coverage depth (the harness itself is not deferred, per above).
- crates.io publication with provenance metadata.

## Consequences

- The scaffold phase (Phase 1 in the main plan) grows slightly in scope: it now explicitly
  includes the full "do now" list above, not just `Cargo.toml` + license files.
- Every subsequent PR must pass through the CI gates from the start — slightly slower iteration
  in the earliest days of the project, in exchange for a Scorecard history that can't be
  shortcut later.
- No `unsafe` is expected in `bloodhound-opengraph`; `ad-tombstone`'s LDAP layer may need to
  justify any `unsafe` explicitly if it arises (unlikely, given pure-Rust `ldap3`).
