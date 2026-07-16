# ADR-0001: Rust, Library-First Workspace (3 Foundational Crates + 1 Binary)

**Status:** Accepted
**Date:** 2026-07-16

## Context

GhostHound could ship as a single script (the original concept docs assumed Python +
`bhopengraph`) or as a deliberately decomposed set of reusable components. The author's prior
project, `skewrun`, established a house style worth following: a pure library crate (`ad-time`)
extractable by other tooling, plus a thin CLI binary orchestrating it — published to crates.io,
dual-licensed, fuzzed, Scorecard-tracked. The goal for GhostHound is the same: build *authority*,
not just a tool, by producing components other AD/BloodHound tooling can depend on.

Two architecture questions needed resolving before writing any code:

**(a) Does GhostHound decompose into genuinely reusable pieces, or is one script the honest shape?**

Research (see `docs/research/tombstone-viability-findings.md`, Finding 6) confirms two real gaps
in the Rust ecosystem:
- No Rust equivalent of Python's `bhopengraph` OpenGraph JSON builder exists.
- No mature, portable crate parses `ntSecurityDescriptor` with full object-ACE/GUID support
  (the `sddl` crate is early-stage, `0.0.16`, and unconfirmed on object-ACE support).

This means GhostHound naturally splits into at least two foundational, independently-useful
pieces (an OpenGraph builder, a security-descriptor parser) plus the AD-tombstone-specific domain
logic and the CLI — matching the `skewrun` pattern but with more surface area, because the domain
has more reusable sub-problems than `skewrun`'s did.

**(b) What language?**

Candidates considered: Python (matches the original concept doc and `bhopengraph`/SCOMHound
precedent), C/C++ (maximum interop reach), Rust (interop reach + memory safety), Go (RustHound-CE's
closest sibling in spirit but no OpenGraph-builder or secdesc prior art either).

The deciding factor is that **interop reach comes from the C ABI, not from the C language**. Any
language that can export `extern "C"` functions and compile to a `cdylib`/`staticlib` is equally
callable from Python (`ctypes`/`cffi`/`pyo3`), C#, Go (`cgo`), Node, or Ruby — a C header doesn't
care what emitted it. Rust does this natively via `cbindgen`. So Rust has the *same* universal
reach as C/C++.

What differs is safety, and this domain is dominated by parsing **untrusted binary input**: LDAP
BER/DER responses, the raw `ntSecurityDescriptor` blob, SIDs, GUIDs. This is precisely the class of
problem where C/C++ memory-safety bugs (buffer overreads on attacker/DC-controlled bytes) become
the vulnerability, in a tool whose entire pitch is "trustworthy foundational security tooling."

Additionally: the Rust BloodHound-collector lineage is already established and SpecterOps-blessed
(`RustHound-CE`, on crates.io, cross-compiled for Linux/Windows/macOS) — building in Rust
compounds an existing authority rather than starting a new one, and sits alongside the author's
own `skewrun` house style.

## Decision

1. **Language: Rust.**
2. **Workspace layout**, mirroring `skewrun`'s `[workspace] members = [...]` + shared
   `[profile.release]` (`lto`, `codegen-units = 1`, `panic = "abort"`, `overflow-checks = true`):

   ```
   crates/
     bloodhound-opengraph/  # LIB — BloodHound OpenGraph JSON builder (generic, zero AD deps)
     ad-secdesc/            # LIB — ntSecurityDescriptor/DACL/ACE parser (zero LDAP/network deps)
     ad-tombstone/          # LIB — LDAP SHOW_DELETED enumeration + tombstone domain model
     ghosthound/            # BIN — CLI orchestrating the three libs
   ```

   **Naming note (added 2026-07-16, post-review):** the builder crate is published as
   `bloodhound-opengraph`, not the shorter `opengraph`. Verified against the crates.io API
   (`GET /api/v1/crates/<name>`, 404 = available) that `opengraph` — along with `opengraph-rs`,
   `open-graph`, `ograph-rs` — is already taken by an entirely unrelated ecosystem: parsers for
   Facebook's **Open Graph *Protocol*** (`<meta property="og:…">` social-link-preview tags), an
   established niche (one listing has 25k+ all-time downloads) with zero relation to BloodHound's
   OpenGraph graph-import format. Publishing as `opengraph` is not just suboptimal, it is
   impossible (name conflict) and would have permanently undermined discoverability by colliding
   with that unrelated crowd. `bloodhound-opengraph` (verified available) is unambiguous and
   defensibly ours — the correct name for a canonical-identity bet. `bhopengraph` (mirroring the
   Python library's name) was considered and rejected: it borrows another project's brand equity
   across registries rather than establishing GhostHound's own.
3. Dependency direction: `ghosthound` → `ad-tombstone` → `ad-secdesc`;
   `ghosthound` → `bloodhound-opengraph`. `bloodhound-opengraph` and `ad-secdesc` depend on
   neither LDAP nor networking, so they remain trivially embeddable and fuzzable in isolation —
   the same property that makes `ad-time` reusable in `skewrun`.
4. Positioning versus `RustHound-CE`: **complementary/standalone**, not a dependency of it.
   GhostHound collects only tombstones and emits an OpenGraph JSON meant to be imported alongside
   a RustHound-CE dump, not instead of it.

## Consequences

- Two of the four crates (`bloodhound-opengraph`, `ad-secdesc`) are the actual "authority" bet —
  their value is measured by adoption outside GhostHound, not just by GhostHound's own correctness.
- `ad-secdesc` is written from scratch under MIT/Apache (ADR-0003, resolved): the only prior art
  found (`janstarke/sddl`) is technically sufficient but GPL-3.0-licensed, disqualifying it as a
  dependency of a permissive foundational crate.
- Committing to Rust means committing to its supply-chain tooling story (`cargo-deny`, `cargo-audit`,
  `cargo-fuzz`, Scorecard) from day one — formalized in ADR-0005.
- No Windows-only APIs anywhere in the libs (unlike `windows-acl`) — everything must run natively
  from a Linux attack host, consistent with the original spec's requirement.
