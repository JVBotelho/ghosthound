# Research Findings: Is Tombstone Reanimation Actually Useful in BloodHound?

**Date:** 2026-07-16
**Purpose:** Before committing to the architecture in ADR-0001..0005, verify the two load-bearing
claims behind GhostHound: (1) that AD tombstone reanimation is a real, high-value attack path, and
(2) that a custom OpenGraph edge can actually participate in BloodHound's attack-path analysis
(e.g. "shortest path to Domain Admins"), not just sit in the graph unreachable by normal queries.
Findings below are the result of web research done specifically to confirm or correct the original
concept docs (`ghostHound.md`, `03-ghostHound-detail.md`, `market-check-03-ghostHound.md`).

**Bottom line:** the idea is sound, but one central claim in the original docs was imprecise in a
way that changes the data model (see Finding 2). This is captured in ADR-0004.

---

## Finding 1 — The Reanimate-Tombstones right is real and confirmed

- `rightsGuid` = `45EC5156-DB7E-47BB-B53F-DBEB2D03C40F`, confirmed against
  [Microsoft's schema reference](https://learn.microsoft.com/en-us/windows/win32/adschema/r-reanimate-tombstones)
  and the [MS-ADTS spec](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/af7bf236-08bc-427e-9e0a-0a0b6dc89dbd).
- It is a **control access right evaluated at the Naming Context root**, not per-object — Microsoft's
  own docs state granting it broadly "can be a security risk because it could permit the user to
  restore an account object that has access to resources the user would not normally have access
  to... the user essentially gains control of this account." This is Microsoft explicitly describing
  the exact abuse primitive GhostHound models. Confirms the concept is not speculative.
- Default grant: Domain Admins only. Matches the original doc's Con #4.

## Finding 2 — CRITICAL: "tombstone" is not one state, it's two, and they differ hugely in value

This is the most important correction to the original spec. AD deletion has **two stages** when the
**AD Recycle Bin** feature is involved:

| Stage | `isDeleted` | `isRecycled` | Attributes | Restorable via |
|---|---|---|---|---|
| **Deleted** (Recycle Bin 1st stage) | `TRUE` | `FALSE` | **Nearly all preserved, including `memberOf`/group membership** | `Restore-ADObject` — full fidelity |
| **Recycled** ("true" tombstone) | `TRUE` | `TRUE` | Stripped to ~60 core attrs; **no `memberOf`, no `servicePrincipalName`, no `userAccountControl`** | Reanimation (`LDAP_SERVER_SHOW_DELETED`) — partial, manual group re-add required |

Sources:
[Microsoft Learn — AD Recycle Bin](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin),
[AskDS — The AD Recycle Bin: Understanding, Implementing...](https://techcommunity.microsoft.com/blog/askds/the-ad-recycle-bin-understanding-implementing-best-practices-and-troubleshooting/396944),
[ldap389 — restore AD object with group membership](https://www.ldap389.info/en/2010/08/05/powershell-restore-ad-object-with-group-membership/).

**Both stages live under the same `CN=Deleted Objects` container and both require
`SHOW_DELETED` to see** — so V1 collection cost is identical either way. The original spec's
"Cons" section already flagged that `memberOf` is lost on reanimation (§03-detail line 186), which
is correct **only for the Recycled stage** — it did not distinguish the two stages, which matters
because:

- **AD Recycle Bin is NOT enabled by default**, even on Windows Server 2022/2025 — it is an
  irreversible opt-in optional feature
  ([Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin)).
  So in a meaningful share of real environments, **every** deleted object goes straight to the
  stripped "Recycled" state — no `Deleted` stage exists at all, and reanimation never restores
  group membership.
- Where Recycle Bin **is** enabled (increasingly common, and best-practice-recommended), an object
  sits in the high-fidelity `Deleted` stage for `msDS-deletedObjectLifetime` (default 180 days)
  before being demoted to `Recycled`. **This is the highest-value case**: restoring a former Domain
  Admin here instantly regains their group membership, no extra step needed.

**Implication for the data model:** GhostHound must model and expose this distinction explicitly
(`isRecycled` as a node property, at minimum), not treat all tombstones as equivalent. See ADR-0004.

## Finding 3 — The flagship "wow" example (TombWatcher) actually used the Deleted stage, not classic reanimation

The market-check doc's key real-world citation, HTB **TombWatcher**, was re-examined directly.
Multiple independent writeups
([0xdf](https://0xdf.gitlab.io/2025/10/11/htb-tombwatcher.html),
[Motasem Hamdan](https://motasemhamdan.medium.com/from-user-to-domain-admin-explained-hackthebox-tombwatcher-writeup-d19dd11bcc52))
confirm: the box restores a deleted `cert_admin` account **"using the Active Directory Recycle
Bin,"** not `LDAP_SERVER_SHOW_DELETED` tombstone reanimation. This means the technique the market
doc leans on as proof of "practical, non-esoteric" value is the **high-fidelity Deleted-stage**
case from Finding 2 — reinforcing that this is the stage worth prioritizing for the strongest,
most legible attack-path story, while the stripped/true-tombstone stage is real but weaker and
needs a different value argument (Finding 4).

## Finding 4 — What still makes the stripped ("true tombstone") stage valuable: orphaned SID ACEs

Even without `memberOf`, a reanimated tombstone's `objectSid` is preserved and reused. Independent
research on **orphaned/stale SIDs in ACLs** confirms: "the original account is deleted, [but] the
orphaned SID still grants access... Orphaned SIDs can be exploited by attackers"
([TechbyJeff](https://www.techbyjeff.net/understanding-orphaned-sids-in-active-directory/); also
[permissionsreporter.com](https://www.permissionsreporter.com/support/orphaned-sids)). Windows
evaluates ACEs by SID at access-check time, not by resolved name — a live object's DACL that still
directly names a deleted principal's SID (common, since AD does not auto-clean ACLs on deletion)
remains fully functional once that SID's identity is reanimated and its credentials taken over.
This is a **different, narrower, but still legitimate** value path than group-membership
restoration: "this reanimated identity may still be directly named in ACEs on live objects,
independent of any group it used to belong to." V1 should surface this as an honest, scoped claim
(a property/flag), not promise full graph cross-referencing (that's a stretch feature — see ADR-0004).

## Finding 5 — BloodHound OpenGraph: custom edges CAN participate in built-in pathfinding

This needed to be confirmed, not assumed, because an early web result claimed "OpenGraph custom
data is Cypher-only" and that the pathfinding UI doesn't work for custom nodes/edges. Fetching the
authoritative docs resolved this:

- The extension definition schema's `relationship_kinds` array has an **`is_traversable`** field:
  *"Controls whether edges of this relationship kind are used for pathfinding and Attack Path
  detection. When `is_traversable` is set to `true`... all edges of that kind inherit the same
  traversability behavior."* ([bloodhound.specterops.io/opengraph/developer/graph-definition](https://bloodhound.specterops.io/opengraph/developer/graph-definition))
- [Traversable and Non-Traversable Edge Types](https://bloodhound.specterops.io/resources/edges/traversable-edges)
  confirms this concept applies to **both BloodHound Enterprise and CE** — not Enterprise-only.
- Best practice ([bloodhound.specterops.io/opengraph/best-practices](https://bloodhound.specterops.io/opengraph/best-practices))
  additionally recommends shipping a **starter Cypher query pack** and **Privilege Zone Rules**
  (Cypher-based tagging to mark custom nodes as high-value/Tier Zero), which is the documented way
  extensions integrate with BloodHound's existing attack-path analysis regardless of UI
  pick-list nuances.

**Conclusion:** setting `is_traversable: true` on the `CanReanimate` relationship kind in
GhostHound's extension schema is both necessary and sufficient (per SpecterOps' own docs) for it
to be included in shortest-path/Tier-Zero queries — the "achievable and useful in owned-to-DA
queries" premise holds, provided the schema is defined correctly (ADR-0004) and a starter Cypher
pack + Privilege Zone Rule ships with it (per best practices).

## Finding 6 — Rust ecosystem re-check for the foundational crates

- **`ldap3`** (Rust): supports custom controls via `RawControl` (→ can send `SHOW_DELETED`,
  OID `1.2.840.113556.1.4.417`), native RFC 2696 paged results, and TLS/LDAPS — confirmed via
  [docs.rs/ldap3](https://docs.rs/ldap3/latest/ldap3/controls/index.html). No blocker.
- **`sspi-rs`** (Devolutions): a cross-platform (Linux-capable) Rust implementation of SSPI with
  NTLM support — [github.com/Devolutions/sspi-rs](https://github.com/Devolutions/sspi-rs). Concrete
  pass-the-hash usage isn't spelled out in the docs directly, but NTLM auth working
  platform-independent is confirmed; PtH is a standard NTLM usage mode this crate should support or
  need only a thin wrapper for. Good foundation for ADR-0002.
- **`sddl` crate — spike completed, resolved in ADR-0003.** The real project behind the
  crates.io listing is **`janstarke/sddl`** (Codeberg,
  [codeberg.org/janstarke/sddl](https://codeberg.org/janstarke/sddl)), a workspace with `sddl` +
  `sddl4web` members. Direct inspection confirmed it **does** parse raw binary
  `SECURITY_DESCRIPTOR` bytes and **does** support object-specific ACEs with GUID fields — its
  `ace::Ace` enum has explicit variants (`ACCESS_ALLOWED_OBJECT_ACE`,
  `ACCESS_DENIED_OBJECT_ACE`, `ACCESS_ALLOWED_CALLBACK_OBJECT_ACE`,
  `ACCESS_DENIED_CALLBACK_OBJECT_ACE`, `SYSTEM_AUDIT_OBJECT_ACE`,
  `SYSTEM_AUDIT_CALLBACK_OBJECT_ACE`) each carrying `object_type: Option<Guid>` and
  `inherited_object_type: Option<Guid>` — precisely the field the Reanimate-Tombstones right is
  gated on. Technically sufficient.
  **But its `Cargo.toml` declares `license = "GPL-3.0"`** — confirmed directly from the repo —
  which is disqualifying for a permissive foundational crate (ADR-0001's whole premise). No other
  candidate closes this gap: `win-security-identifier`/`-parsing`/`-macro` (crates.io) only handle
  SIDs, not security descriptors; `windows-acl` remains Win32-only; `openzl_sddl_derive` is an
  unrelated project (OpenZL's Simple Data Description Language, not Windows SDDL); `taskschd` and
  `zeusd` are unrelated (Task Scheduler demo, GPU power daemon).
  **Decision (ADR-0003): write `ad-secdesc` from scratch under MIT/Apache**, using `sddl` only as
  a black-box test oracle in development (never linked/shipped) — this reframes `ad-secdesc` from
  "fills an absence" to "fills a *licensing* gap," arguably a stronger authority claim: the only
  permissively-licensed Rust binary AD-security-descriptor parser.

## Finding 7 — The builder crate cannot be named `opengraph`: taken by an unrelated ecosystem

Flagged by the user reviewing a crates.io search result list. All of `opengraph` (v0.2.4, 25k+
all-time downloads), `opengraph-rs`, `open-graph`, `ograph-rs`, plus adjacent tools (`og-img`,
`webpage`/`webpage-info`, `html-meta-scraper`, `siteone-crawler`) belong to a **completely
different, unrelated ecosystem**: parsers/generators for Facebook's **Open Graph *Protocol*** —
the `<meta property="og:title">`/`og:image` HTML tags that produce social-media link-preview
cards. This is a same-name, different-thing collision with BloodHound's OpenGraph graph-import
format; the two share nothing beyond the English words.

Verified directly against the crates.io API (`GET https://crates.io/api/v1/crates/<name>`; a 404
means available, confirmed against known-existing crates `opengraph` and `ad-time` as a control
before trusting 404s as "free"):

| Name | Status |
|---|---|
| `opengraph` | **Taken** (v0.2.4, OGP HTML parser — unrelated) |
| `opengraph-rs`, `open-graph`, `ograph-rs` | Taken (same OGP ecosystem) |
| `bloodhound-opengraph` | **Available** |
| `bhopengraph` | Available (but rejected — borrows the Python library's own brand) |
| `ad-secdesc` | **Available** |
| `ad-tombstone` | **Available** |
| `ghosthound` | **Available** |

**Decision (recorded in ADR-0001):** the builder crate is published as **`bloodhound-opengraph`**,
not `opengraph` — publishing under the latter is not merely suboptimal, it is impossible (name
conflict), and would have wrecked discoverability by competing with an established, unrelated
25k-download crate for the same search term. This also means the "is our OpenGraph builder
unique/canonical-worthy" question resolves separately from naming: functionally yes (no Rust
BloodHound-OpenGraph builder library exists, confirmed in Finding 6), but canonicity requires an
unambiguous name, which `opengraph` could never have provided even if it had been free.

---

## Net assessment

The idea is **achievable and useful**, with three corrections to the original framing:
1. Model tombstone state (Deleted vs Recycled) explicitly — don't claim uniform value.
2. `ad-secdesc` is "fill a *licensing* gap" rather than "fill an absence of prior art" —
   technically-sufficient prior art (`janstarke/sddl`) exists but is GPL-3.0, so ADR-0003
   concludes "write a parser from scratch under MIT/Apache," using `sddl` only as a private
   test oracle. Workspace stays at 3 lib crates + 1 bin, no collapse.
3. The OpenGraph builder crate is named `bloodhound-opengraph`, not `opengraph` — the latter is
   taken by an unrelated ecosystem (Finding 7) and would have been both unavailable and
   discoverability-damaging.

Everything else in the original concept (LDAP mechanics, OpenGraph mechanics, RustHound-CE
positioning) held up under verification.
