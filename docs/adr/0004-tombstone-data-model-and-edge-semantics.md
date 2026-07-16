# ADR-0004: Tombstone Data Model Must Distinguish Recycle-Bin State, and `CanReanimate` Must Set `is_traversable`

**Status:** Accepted
**Date:** 2026-07-16

## Context

Two premises underpin the entire project: (1) tombstone reanimation is a real, valuable attack
path, and (2) a custom OpenGraph edge can actually be found by BloodHound's built-in
pathfinding (e.g. "shortest path to Domain Admins"), not just sit in the graph reachable only by
hand-written Cypher. Both needed verification, not assumption, before finalizing the schema in
`03-ghostHound-detail.md`. Full detail in `docs/research/tombstone-viability-findings.md`
(Findings 2, 3, 4, 5); this ADR records the resulting design decisions.

### Problem 1: "tombstone" is not a single state

AD deletion has two distinct stages when the **AD Recycle Bin** optional feature is in play:

- **`Deleted`** (`isDeleted=TRUE`, `isRecycled=FALSE`): nearly all attributes preserved,
  **including `memberOf`/group membership**. `Restore-ADObject` here is a full-fidelity restore.
- **`Recycled`** ("true" tombstone) (`isDeleted=TRUE`, `isRecycled=TRUE`, or *any* deleted object
  at all if Recycle Bin is disabled): stripped to ~60 core attributes — no group membership, no
  `userAccountControl`, no SPNs.

AD Recycle Bin is **not enabled by default** even on current Windows Server versions, so both
paths are common in the wild: many domains only ever produce `Recycled`-state objects; domains
that opted in produce a `Deleted`-state window (default 180 days) first. HTB TombWatcher — the
market doc's flagship "this is real and practical" citation — turned out on inspection to exploit
the **`Deleted`** stage specifically (full fidelity, via AD Recycle Bin restore), not classic
`SHOW_DELETED` reanimation of a stripped tombstone. Treating all tombstones as equivalent, as the
original node model implicitly did, would overstate the value of the common `Recycled` case and
undersell the `Deleted` case.

Both stages live under the same `CN=Deleted Objects` container and are both retrieved with the
same `SHOW_DELETED` control — so this is a modeling correction, not a collection-cost increase.

### Problem 2: does a custom edge kind actually get traversed by BloodHound's pathfinding?

Confirmed via the OpenGraph developer docs: the extension schema's `relationship_kinds` array has
an `is_traversable` boolean — *"Controls whether edges of this relationship kind are used for
pathfinding and Attack Path detection"* — and this applies to **both CE and Enterprise**, per
`bloodhound.specterops.io/resources/edges/traversable-edges`. So the mechanism to make
`CanReanimate` genuinely show up in "shortest path to Domain Admins"-style queries exists and is
documented; it was not previously verified in the plan.

## Decision

**Node model** — every `Tombstone*` node kind carries these properties (in addition to those
already listed in `03-ghostHound-detail.md`):

- `is_recycled` (bool) — `isRecycled` as read from LDAP.
- `recycle_bin_enabled` (bool) — whether the domain has the AD Recycle Bin optional feature on
  (determined once via RootDSE `msDS-EnabledFeature` lookup, applied to all nodes in the run).
- `group_membership_recoverable` (bool) — derived: `true` only when `is_recycled == false`
  (i.e. the `Deleted` stage). This is the property that should drive UI/Cypher framing of
  "restoring this instantly regains its former privileges" vs. "restoring this regains only the
  identity/SID, not its former privileges."

**Edge model** — keep `CanReanimate` as designed, but:
- Set **`is_traversable: true`** on the `CanReanimate` relationship kind in the extension
  definition schema. This is the specific, confirmed mechanism that makes it eligible for
  built-in pathfinding — do not rely on Cypher-only discovery.
- Ship the required starter Cypher query pack and at least one **Privilege Zone Rule** tagging
  privileged tombstones (e.g. a `TombstoneUser` whose `lastknownparent` matches a Tier-Zero OU) as
  high-value, per SpecterOps' documented best practice for integrating with existing attack-path
  analysis — this is additive to `is_traversable`, not a substitute for it.

**Scope boundary for the "stale SID in live ACEs" value path** (Finding 4): V1 surfaces this as an
honest, narrow claim — a boolean/count property noting the object's SID's presence is *possible*
to check, not a promise of automatic cross-referencing against the entire live graph. Full
cross-referencing (scanning every live object's DACL for the tombstone's orphaned SID) is
explicitly a stretch feature, not V1, and should be scoped as its own follow-up ADR if pursued —
it is a materially larger data-access problem (requires reading DACLs off *live* objects too, not
just tombstones) than anything currently in the V1 plan.

## Consequences

- `ad-tombstone`'s enumeration must read `isRecycled` (already in the planned attribute list
  implicitly via `isDeleted`; add `isRecycled` explicitly) and do one extra RootDSE feature lookup
  per run.
- Documentation (README, node/edge docs for the OpenGraph Management page) must state the
  `group_membership_recoverable` distinction plainly — this is a correctness-of-claims issue, not
  just a nice-to-have, given Finding 3 showed the original framing risked overstating the common
  case.
- `is_traversable: true` must be set explicitly when authoring the extension's `model.json` —
  this was previously an implicit assumption in the plan and is now a required, named field.
- No change to crate boundaries or language decision (ADR-0001) — this ADR only refines the
  node/edge schema inside `ad-tombstone`/`ghosthound` and the `model.json` the tool ships.
