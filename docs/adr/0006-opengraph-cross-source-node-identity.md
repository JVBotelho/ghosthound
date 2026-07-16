# ADR-0006: Bridging GhostHound's OpenGraph Nodes Into the Real AD Graph

**Status:** Accepted
**Date:** 2026-07-16

## Context

Live homelab testing (BloodHound CE, current release, with RustHound-CE providing the base AD
graph) surfaced a platform-level limitation while validating `GhostHound_WasMemberOf` — the edge
that lets a reanimated tombstone's preserved group membership (see ADR-0004) actually appear as a
traversable path back into e.g. Domain Admins.

The edge's target is a well-known principal (a SID like Domain Admins' `...-512`) that RustHound-CE
already ingested as a real `:Group` node. Two ways of referencing it at ingest time were tried
against the live instance, and both failed for the same underlying reason:

1. **`match_by: "id"`, no `kind`.** BloodHound's OpenGraph ingest scopes the relationship
   endpoint's identity to the ingest's own `source_kind` (here, `GhostHound`) regardless of the
   objectid value referenced. This creates a **second, untyped node** sharing the real group's
   `objectid` property, rather than attaching to the existing `:Group` node — confirmed by
   querying both nodes back (`MATCH (x) WHERE x.objectid = <sid> RETURN x, labels(x)` returned two
   distinct nodes, one `Active Directory | Group`, one bare `OpenGraph | GhostHound`).
2. **`match_by: "property"`, `kind: "Group"`.** BloodHound's `resolveIngestibleEndpoint` does
   perform a genuine graph-wide lookup here (not scoped to our source) and correctly finds the
   real node. But the *write* path that follows still scopes node identity to the ingest's own
   `source_kind`, and now also attaches the `Group` label to the new node it creates for that
   identity — which collides with BloodHound's own uniqueness constraint on `(:Group, objectid)`.
   Confirmed via the BloodHound container's own logs: `Neo4jError:
   Neo.ClientError.Schema.ConstraintValidationFailed (Node(48) already exists with label
   ``Group`` and property ``objectid`` = '...-512')` — and because this is a hard error, the
   **entire file's ingest task fails**, not just that one edge.

This isn't a bug specific to this BloodHound version so much as an intentional boundary: built-in
AD/Azure collector data is ingested under a shared privileged identity (`ad.Entity` /
`azure.Entity` in BloodHound's own source), and `FetchNodeByObjectIDIncludeOpenGraph` in
BloodHound's source explicitly excludes that identity space when resolving OpenGraph nodes
(`query.Not(query.Kind(query.Node(), ad.Entity, azure.Entity))`). Third-party OpenGraph extensions
are deliberately kept from writing into that space at ingest time — reasonably so, since otherwise
any custom extension could mutate or relabel a tenant's real AD principals.

A workaround considered and rejected: emit tombstone data disguised as legacy
SharpHound/RustHound-CE-format JSON (which *does* ingest under `ad.Entity` and would genuinely
merge at ingest time). Rejected because it makes a reanimation-contingent relationship (true only
*if* someone reanimates the tombstone) visually and structurally indistinguishable from a real,
currently-valid group membership — the exact kind of ambiguity OpenGraph's custom node/relationship
kinds exist to avoid in a tool whose entire premise is correctness of attack-path claims (ADR-0004).

The key realization that unblocked this: the constraint above only fires on **creating a node**
with a duplicate `(label, objectid)` pair. It does not apply to creating a **relationship** between
two nodes that already exist. A `MERGE` that matches both endpoints by their existing identity and
only creates the edge between them never touches node creation at all, so it's unaffected.

## Decision

- `GhostHound_WasMemberOf`'s (and any future edge referencing an existing base AD/Azure principal)
  target endpoint uses a plain `match_by: "id"` reference at ingest time (option 1 above) — it
  creates an untyped placeholder node rather than failing the ingest.
  `ad_tombstone::resolve_object_sid`'s doc comment records why `match_by: "property"` + `kind`
  isn't used instead, so this isn't silently reintroduced.
- `crates/ad-tombstone/bridge_shadow_nodes.cypher` is run once against Neo4j after every
  GhostHound import. It matches each untyped placeholder node to the real node sharing its
  `objectid` and `MERGE`s a `GhostHound_SameAs` relationship between them — a relationship-only
  write, so it doesn't hit the node-uniqueness constraint that blocks a direct ingest-time fix.
  This is idempotent (safe to re-run) and restores real graph traversability: a plain
  `shortestPath(...)` query now walks `GhostHound_WasMemberOf` into the placeholder and
  `GhostHound_SameAs` into the real `Group` node, confirmed against the live lab.
- `GhostHound_SameAs` is registered in `model.json` (`is_traversable: true`) like the other
  relationship kinds.
- BloodHound CE's own Cypher search bar rejects the bridge script ("updating clauses are not
  supported" — that bar is read-only for any write, not just `MERGE`). The bridge must be run
  directly against Neo4j, e.g. `docker exec -i <graph-db-container> cypher-shell -u neo4j -p
  <password> < bridge_shadow_nodes.cypher`. The same restriction applies to
  `privilege_zones.cypher` (its `SET` is also an updating clause) — the README documents both as
  needing `cypher-shell`, not the search bar.
- The underlying ingest-time limitation (an OpenGraph edge can't merge into a pre-existing
  base-AD/Azure node's identity) is still worth reporting upstream to SpecterOps/BloodHound, since
  their own OpenGraph documentation implies `match_by: "property"` supports cross-source linking,
  which the write path does not actually deliver. The bridge script is a working solution
  regardless of whether that gets addressed. Issue draft ready to file:
  `docs/dev/bloodhound-ce-issue-opengraph-cross-source-identity.md`.

## Consequences

- Every GhostHound import against a domain with existing SharpHound/RustHound-CE data needs one
  extra manual step (running `bridge_shadow_nodes.cypher` via `cypher-shell`, not the BloodHound
  UI) before `GhostHound_CanReanimate`/`GhostHound_WasMemberOf` paths are traversable into the rest
  of the graph. README documents this as part of the standard import sequence.
- If BloodHound changes the underlying ingest behavior upstream, the bridge script becomes
  unnecessary but remains harmless (its `MERGE` finds nothing to bridge once nodes already share
  one real identity).
- No change to the node/edge *model* from ADR-0004 — `group_membership_recoverable` and
  `GhostHound_WasMemberOf` remain correct as data; this ADR only adds the bridge needed to make
  that data traversable given a real platform constraint on ingest-time graph fusion.
