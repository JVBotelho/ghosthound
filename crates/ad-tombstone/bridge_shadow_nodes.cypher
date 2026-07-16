// Bridge GhostHound's OpenGraph shadow nodes into the real AD graph
//
// BloodHound's OpenGraph ingest scopes relationship-endpoint node identity to the ingest's own
// source kind, so a GhostHound edge referencing an existing AD principal (e.g. Domain Admins,
// via CanReanimate/WasMemberOf) creates a separate untyped "shadow" node sharing that principal's
// objectid, rather than attaching to the real node RustHound-CE/SharpHound already created (see
// docs/adr/0006-opengraph-cross-source-node-identity.md for the verified root cause).
//
// This script creates a real, traversable edge from each shadow node to its corresponding real
// node, purely by matching on the objectid they already share. It does not create any node, so
// it does not touch the uniqueness constraint that blocks a direct fix at ingest time. Run this
// once after every GhostHound import (safe to re-run: MERGE makes it idempotent).
//
// BloodHound CE's own Cypher search bar is read-only and will reject this ("updating clauses are
// not supported") -- run it directly against Neo4j instead, e.g.:
//   docker exec -i <graph-db-container> cypher-shell -u neo4j -p <password> < bridge_shadow_nodes.cypher

// Scoped as an allowlist, not a denylist: BloodHound labels every node it creates for a given
// ingest with that ingest's source_kind (here, the literal label "GhostHound"), in addition to
// any specific kind declared for it -- so a shadow is precisely a GhostHound-sourced node that
// ISN'T one of GhostHound's own real, declared kinds. A denylist of "known other kinds" (Group,
// User, Base, Azure/ADCS kinds, other OpenGraph extensions' kinds, ...) would need updating every
// time BloodHound or another extension adds a kind, and would still risk bridging unrelated nodes
// that happen to share an objectid. `real` is bounded the same way, from the other direction: it
// must NOT carry the GhostHound label, i.e. it must come from a different ingest source entirely.
MATCH (shadow:GhostHound)
WHERE NOT shadow:GhostHound_TombstoneUser
  AND NOT shadow:GhostHound_TombstoneComputer
  AND NOT shadow:GhostHound_TombstoneGroup
  AND shadow.objectid IS NOT NULL
MATCH (real)
WHERE real.objectid = shadow.objectid AND NOT real:GhostHound AND id(real) <> id(shadow)
MERGE (shadow)-[:GhostHound_SameAs]->(real)
RETURN count(*) AS bridges_created;
