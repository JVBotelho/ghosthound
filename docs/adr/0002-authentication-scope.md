# ADR-0002: V1 Authentication Scope — Simple Bind/LDAPS + NTLM, Kerberos Deferred

**Status:** Accepted (amended 2026-07-16 — see Amendment: NTLM descoped from V1)
**Date:** 2026-07-16

## Context

SharpHound/impacket-style tools conventionally support several auth modes: plaintext
username/password, NTLM hash (pass-the-hash), Kerberos ticket/ccache (pass-the-ticket), and
`-no-pass`/interactive prompts. Supporting all of them raises the CLI's practical utility on real
engagements, but each mode is a separate implementation and testing burden, and this is a V1.

Research needed to confirm what's actually available in Rust without reaching for a Python
subprocess or an FFI shim to Kerberos C libraries:

- **Simple bind / LDAPS**: natively supported by the `ldap3` crate (TLS via `native-tls` or
  `rustls`), no gap.
- **NTLM incl. pass-the-hash**: `sspi-rs` ([github.com/Devolutions/sspi-rs](https://github.com/Devolutions/sspi-rs))
  is a maintained, cross-platform (Linux-capable) Rust implementation of SSPI with NTLM support,
  confirmed via docs.rs. This is a viable, non-exotic dependency.
- **Kerberos/ccache (pass-the-ticket)**: no equally mature, confirmed-in-research Rust crate was
  found with the same "just works on Linux, well-documented" profile as `sspi-rs`'s NTLM path in
  the time available for this planning pass. `sspi-rs` does advertise broader SSPI/GSSAPI
  ambitions, and `cross-krb5` exists as another candidate, but neither was verified in depth here.
  Committing to a specific Kerberos approach now, without that verification, risks a V1 blocker
  on the least-differentiating auth mode (Kerberos support does not change *what data* GhostHound
  can collect — only how the bind happens).

## Decision

- **V1 ships:** simple bind (user/password) + LDAPS/StartTLS, and NTLM bind including
  pass-the-hash via `sspi-rs`.
- **Kerberos/ccache (pass-the-ticket) is explicitly deferred**, not silently dropped. The CLI
  reserves the `-k`/`--kerberos` flag and `KRB5CCNAME` env convention now (matching
  impacket/SharpHound conventions) so the surface is stable when it's implemented, but the flag
  is documented as "not yet implemented" rather than wired to a rushed/unverified integration.
- Before implementing Kerberos, do a dedicated spike evaluating `sspi-rs`'s GSSAPI path vs
  `cross-krb5` against a real lab DC, rather than assuming either from documentation alone.

## Consequences

- V1 covers the two auth modes pentesters hit most often in practice (plaintext creds, PtH),
  without gating the release on unverified Kerberos plumbing.
- Anyone scripting GhostHound with `-k` in V1 gets a clear "not implemented" error rather than
  silent misbehavior — flag exists, behavior doesn't yet.
- `Administrators`-equivalent rights are required to read `CN=Deleted Objects` regardless of bind
  method — this is a hard prerequisite independent of auth mode, documented in the README (carried
  over from the original spec's Cons section).

## Amendment: NTLM descoped from the V1 CLI (found during code review, not previously recorded)

The Decision above committed V1 to shipping NTLM bind including pass-the-hash via `sspi-rs`. The
implemented `ghosthound` CLI does not: it accepts a `--ntlm` flag solely to reject it with a clear
error — *"NTLM authentication is currently disabled due to upstream dependencies (sspi-rs) failing
strict security checks on the latest compiler toolchain. Please use Simple Bind."* — and contains
no NTLM code path at all. This descope was made silently in code with no corresponding ADR update,
which a code review flagged as a documentation/decision-sync gap: a reader of the Decision section
above would reasonably believe NTLM/PtH shipped in V1.

**Recorded now:** NTLM/pass-the-hash is **out of V1's actual shipped scope**, deferred alongside
Kerberos, for the reason stated in the CLI's own error message (an `sspi-rs` toolchain/security-check
incompatibility encountered during implementation, not evaluated in the original research pass
behind this ADR). The `-k`/`--ntlm` flags both exist and both currently error rather than silently
misbehave, consistent with this ADR's own principle for Kerberos. V1 ships **only** simple
bind/LDAPS. Re-evaluating `sspi-rs` (or an alternative NTLM implementation) is future work, to be
spiked the same way Kerberos is scoped to be (Decision, bullet 3) before being wired in.
