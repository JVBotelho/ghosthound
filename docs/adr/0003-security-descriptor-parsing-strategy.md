# ADR-0003: `ad-secdesc` Is Written From Scratch — The Only Sufficient Prior Art Is GPL-3.0

**Status:** Accepted
**Date:** 2026-07-16 (spike completed same day)

## Context

The original plan assumed `ad-secdesc` fills a "confirmed, zero-prior-art gap": the only
Rust crate found for ACL work, `windows-acl` (Trail of Bits), is Windows-API-bound and therefore
useless on a Linux attack host.

Initial research (see `docs/research/tombstone-viability-findings.md`, Finding 6) found a
`sddl` crate listed on crates.io (`v0.0.16`) claiming to parse raw binary `SECURITY_DESCRIPTOR`
bytes, which would have made that assumption incomplete. This ADR was left **Proposed**, pending
a spike, because two things were unconfirmed: object-specific ACE/GUID support, and license.

## Spike findings

The user pointed at the actual project — **`janstarke/sddl`** on Codeberg
(`https://codeberg.org/janstarke/sddl`) — which is the real, actively-maintained implementation
behind the crates.io listing (a Cargo workspace with members `sddl` and `sddl4web`). Direct
inspection resolved both open questions:

1. **Object-ACE/GUID support: yes, fully sufficient.** The crate's `ace::Ace` enum has explicit
   variants for every object-specific ACE type —
   `ACCESS_ALLOWED_OBJECT_ACE`, `ACCESS_DENIED_OBJECT_ACE`,
   `ACCESS_ALLOWED_CALLBACK_OBJECT_ACE`, `ACCESS_DENIED_CALLBACK_OBJECT_ACE`,
   `SYSTEM_AUDIT_OBJECT_ACE`, `SYSTEM_AUDIT_CALLBACK_OBJECT_ACE` — each carrying
   `object_type: Option<Guid>` and `inherited_object_type: Option<Guid>`. This is exactly the
   field the Reanimate-Tombstones right (`rightsGuid = 45EC5156-DB7E-47BB-B53F-DBEB2D03C40F`,
   Finding 1) is gated on. It parses the binary blob directly
   (`SecurityDescriptor::try_from(&binary_data[..])`), is a pure-Rust `Cargo.toml` workspace with
   no confirmed Win32 dependency, and depends on `uuid` for its `Guid` type.

2. **License: GPL-3.0 — disqualifying.** Confirmed directly from the repo's `Cargo.toml`
   (`license = "GPL-3.0"`). GPL-3.0 is viral copyleft: linking it (even as a normal, non-dev
   dependency) into `ad-secdesc` would force `ad-secdesc`, `ad-tombstone`, and `ghosthound` all
   to GPL-3.0. This directly contradicts the reason the whole workspace exists (ADR-0001):
   permissively-licensed (MIT/Apache dual) foundational crates other tooling — including closed
   or differently-licensed commercial red-team tooling — can freely embed. A GPL-encumbered
   foundation is not a foundation for this project's goals.

No other candidate surfaced. `win-security-identifier` (+ its `-parsing`/`-macro` siblings) only
handles SIDs, not security descriptors/ACLs — insufficient regardless of license.
`windows-acl` remains Win32-only.

## Decision

**Write `ad-secdesc` from scratch, under MIT/Apache dual license.** This is no longer a
"greenfield gap" claim in the weak sense (absence of prior art) — it is a **licensing gap**: the
only Rust implementation that does what's needed technically (`janstarke/sddl`) cannot be used
because of its license. Filling that gap with a permissive equivalent is, if anything, a
*stronger* authority claim than originally framed: GhostHound's `ad-secdesc` becomes *the only
permissively-licensed Rust parser of binary AD security descriptors*, filling a gap `sddl` itself
cannot fill for MIT/Apache-licensed downstream consumers.

Concretely:
1. `ad-secdesc` implements its own binary parser (little-endian, per MS-DTYP `SECURITY_DESCRIPTOR`),
   covering the same object-ACE surface confirmed above (`object_type`/`inherited_object_type`
   GUIDs on all six object-ACE variants), under MIT/Apache, with `thiserror` + `uuid`, zero Win32
   deps — as in the original plan.
2. **`janstarke/sddl` is used only as a black-box test oracle during development** — parse the
   same captured `ntSecurityDescriptor` blobs (including at least one carrying the
   Reanimate-Tombstones right) through both implementations and diff the decoded ACEs, plus
   cross-check against the public MS-DTYP spec text. No GPL source is read-and-adapted into
   `ad-secdesc`; only observed input/output behavior informs test expectations — this keeps
   `ad-secdesc` cleanly MIT/Apache, not a derivative work.
3. The oracle harness itself must **never** be a dependency (normal or `dev-dependency`) of the
   published `ad-secdesc` crate — `cargo test` on the published crate must not pull GPL code. Keep
   it in a separate, unpublished workspace member (or an `xtask`) gated behind a non-default
   feature/CI job, and let `cargo deny`'s license policy enforce "no copyleft in the shipped
   graph" as a hard CI gate (ADR-0005).
4. Consider filing upstream issues/test-corpus contributions to `janstarke/sddl` as a courtesy —
   it's a legitimate, well-built project; the constraint here is purely about what GhostHound's
   own license commitments require, not a quality judgment.

## Consequences

- No 2-crate collapse: the workspace stays at **3 lib crates + 1 bin** (`bloodhound-opengraph`,
  `ad-secdesc`, `ad-tombstone`, `ghosthound`), as in the original plan — the earlier "might
  collapse to 2" contingency is resolved. (Builder crate name is `bloodhound-opengraph`, not
  `opengraph` — see ADR-0001's naming note: `opengraph` is taken by an unrelated crates.io
  ecosystem, Facebook Open Graph *Protocol* parsers.)
- `ad-secdesc` implementation is not shortened by reuse, but its test *confidence* is
  strengthened by having a working reference implementation to diff against, without any
  licensing entanglement.
- `cargo-fuzz` panic-safety testing remains mandatory regardless (attacker/DC-influenced blob),
  independent of this decision. `proptest` was considered here but isn't part of the workspace --
  fuzzing already covers the panic-safety goal this ADR cared about, so it wasn't added on top.
- Adds one CI-enforced check: `cargo deny` must ban GPL/copyleft licenses workspace-wide, so a
  future contributor can't accidentally reintroduce a GPL dependency.
