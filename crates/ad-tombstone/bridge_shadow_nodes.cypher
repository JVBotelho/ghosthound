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

MATCH (shadow)
WHERE shadow.objectid IS NOT NULL
  AND NOT shadow:Group AND NOT shadow:User AND NOT shadow:Computer
  AND NOT shadow:Domain AND NOT shadow:GPO AND NOT shadow:OU AND NOT shadow:Container
MATCH (real)
WHERE real.objectid = shadow.objectid AND id(real) <> id(shadow)
MERGE (shadow)-[:GhostHound_SameAs]->(real)
RETURN count(*) AS bridges_created;
