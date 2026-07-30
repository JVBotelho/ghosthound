# ADR-0007: `CanReanimate` Covers Ownership and DACL-Write Paths, Tagged by Mechanism

**Status:** Accepted
**Date:** 2026-07-30

## Context

Until now, GhostHound emitted `GhostHound_CanReanimate` only for principals holding the formal
**Reanimate-Tombstones** control access right (extended right GUID
`45ec5156-db7e-47bb-b53f-dbeb2d03c40f`), read off the domain naming-context root per ADR-0004.

That misses a second, equally usable path. A principal who **owns** a tombstoned object, or holds
**`WRITE_DAC`** (0x00040000) or **`WRITE_OWNER`** (0x00080000) on it, can rewrite that object's
`nTSecurityDescriptor` to grant itself the Reanimate-Tombstones right — or manipulate the object out
of `CN=Deleted Objects` directly — without already holding the extended right. An owner can do this
regardless of what the DACL says, which is exactly why parsing only the ACE list is not sufficient.

Confirmed in a lab domain (`tombwatcher.htb`): `bloodyAD get writable` reports a plain user with
`OWNER: WRITE` / `DACL: WRITE` on several tombstoned `cert_admin` objects, while GhostHound's ingest
JSON for those tombstones contained no edges at all for that user, and no owner/ACL data on the
nodes. The information was being discarded at collection time — `fetch_tombstones` never requested
`nTSecurityDescriptor` for the tombstones themselves, only for the NC root.

## Decision

**Collect each tombstone's own descriptor, with the `SD_FLAGS` control.** `fetch_tombstones`
requests `nTSecurityDescriptor` alongside the existing attributes — but requesting the attribute is
not sufficient on its own. Absent `LDAP_SERVER_SD_FLAGS_OID` (`1.2.840.113556.1.4.801`), AD attempts
to return the entire descriptor including the SACL; reading a SACL requires `SeSecurityPrivilege`,
and instead of returning the readable parts the DC **omits the attribute from the response
entirely**. Verified against `tombwatcher.htb`: as the plain user `john`, all 3 tombstones *and* the
domain NC root came back with no descriptor at all until the control was added, which reads
identically to "no ACL data exists" — the same class of silent data loss this ADR exists to fix. The
control is sent with flags `OWNER|GROUP|DACL` (0x07, SACL excluded since nothing here needs it) and
non-critical, so an unsupporting DC degrades to the old behavior instead of failing the search. It's
sent on the domain-NC-root read in `check_reanimate_rights` for the same reason.

`TombstoneObject::from_entry` parses both halves of the descriptor: the
`OwnerSid` (new `owner_sid` field) and the DACL. A missing attribute (no `READ_CONTROL` for the
bound principal) or an unparseable blob degrades to "no ownership/ACL data" for that object rather
than failing the run; the CLI reports the count on stderr so an analyst isn't left reading absence
of data as absence of control.

**One analysis function, no LDAP.** `analyze_reanimation_control(&SecurityDescriptor)` is the whole
of the rights logic and is pure, so every mechanism is unit-testable against hand-built descriptor
blobs. It keeps the existing correctness gates — deny/audit ACE types (`is_allow_ace`) and
inherit-only ACEs (`applies_to_self`) are excluded, since both can carry the same access mask and
object-type GUID as a real grant.

**Four mechanisms, in precedence order** (`ReanimateMechanism`): `reanimate_right`, `owner`,
`write_dac`, `write_owner`.

- **The `reanimate_right` test is stricter on an individual object than at the NC root.** At the root,
  an unscoped control-access ACE (or `GenericAll`) covers every extended right, Reanimate-Tombstones
  included — `grants_reanimate_right_at_nc_root`. On a tombstone it does not: the right is *validated*
  at the naming-context root, so broad rights on the object confer the ability to rewrite its
  descriptor, not the right itself. Object-level `reanimate_right` therefore requires an ACE naming
  the GUID explicitly (`grants_reanimate_right_on_object`), which is what an ACE inherited from
  `CN=Deleted Objects` looks like. `GenericAll` on a tombstone maps to `write_dac` + `write_owner`
  instead, per the generic-to-specific mapping. Labeling it `reanimate_right` would report an
  ACL-rewrite path as a formally-held right — the exact overstatement these labels exist to prevent.
  Caught in the lab: john's `GenericAll` on the `cert_admin` tombstones first surfaced as
  `source: "reanimate_right"`, when `write_dac` is the truthful answer.
- `GENERIC_WRITE` (0x40000000) is not treated as a descriptor-write grant: for a directory object it
  maps to write-property/self, which does not include `WRITE_DAC`.
- `object_type` is ignored when testing `WRITE_DAC`/`WRITE_OWNER`. An object ACE's GUID narrows only
  the AD-specific rights (control-access, read/write-property, create/delete-child); the standard
  rights always apply to the object as a whole.
- Ownership of the **domain NC root** is deliberately *not* treated as a reanimation path by
  `check_reanimate_rights`. That function answers "who holds the right domain-wide", and an
  ACL-rewrite path on the NC root is a far broader finding than tombstone reanimation — it belongs
  to a different tool, not smuggled in as a `CanReanimate` edge.

**One edge per principal per tombstone, tagged with its mechanisms.** The domain-wide right and the
per-object descriptor can both name the same principal, so the CLI merges mechanisms per SID and
emits a single edge carrying:

- `source` — the strongest mechanism, as one scalar string, so a Cypher query can filter without
  list handling;
- `sources` — every mechanism that qualified.

This matches the de-duplication rule `check_reanimate_rights` already applied to its own SID list
(one edge per principal, not one per qualifying ACE). The tombstone node also carries `ownersid`,
because "who owns this tombstone" is a fact an analyst reads directly off the object and is what
makes an `owner`-sourced edge explainable.

## Consequences

- The mechanism distinction is operational, and analysts must be able to see it: `reanimate_right`
  is usable as-is, while the other three require first rewriting the tombstone's DACL or ownership —
  a loud, auditable extra step. Flattening all four into one undifferentiated edge would overstate
  the immediacy of the ownership paths, the same failure mode ADR-0004 corrected for
  `Deleted`-vs-`Recycled`.
- `source`/`sources` are edge property *values*, not schema: BloodHound's OpenGraph extension
  definition declares node and relationship *kinds* only, so `model.json` needs no new field for
  them — its `GhostHound_CanReanimate` description documents them instead. The edge kind name and
  `is_traversable: true` are unchanged, so existing queries keep working; `bridge_shadow_nodes.cypher`
  and `privilege_zones.cypher` are untouched.
- The starter query pack moved from a single `queries.json` to one file per query under
  `crates/ad-tombstone/queries/`, and gained queries for the new mechanisms (ACL-rewrite-only paths,
  non-Tier-Zero holders, per-principal lookup) plus collection-health checks (unreadable descriptors,
  unbridged placeholders). The old file was in BloodHound *Legacy*'s `customqueries.json` schema
  (`{"queries": [{"queryList": [...]}]}`), which BloodHound CE cannot import at all: CE's
  `POST /api/v2/saved-queries/import` unmarshals each file into a single
  `TransferableSavedQuery{query, name, description}` and rejects arrays or wrapper objects. Several of
  those queries also returned scalar properties rather than nodes/paths, which CE's Cypher view
  renders as an empty result — every query in the pack now returns nodes or paths.
- `fetch_tombstones` now requests one extra (potentially large) attribute per tombstone. No
  additional round-trips: it rides along on the existing paged search.
- Emitted principal IDs are domain-scoped for well-known SIDs (`<DOMAIN FQDN>-<SID>`, e.g.
  `TOMBWATCHER.HTB-S-1-5-32-544`), matching SharpHound/RustHound-CE's own `objectid` convention.
  Without it, `bridge_shadow_nodes.cypher` has no shared `objectid` to match on and those shadows stay
  stranded — observed in the lab, where SYSTEM/Administrators/Account Operators were the only
  unbridged nodes. Domain SIDs (`S-1-5-21-*`) are already unique and pass through untouched, so the
  bridge script itself needs no loosening (no fuzzy suffix matching, no cross-domain ambiguity).
- Tombstone descriptors are frequently owned by `Domain Admins`/`Administrators`, so expect
  `owner`-sourced edges from those principals on most tombstones. They are accurate — a Domain Admin
  really can reanimate — and no filtering is applied, since suppressing "obvious" high-privilege
  principals is a presentation choice for the consumer, not something the collector should decide.
