// Privilege Zone Rule for High-Value Tombstones
// Marks Tombstone users/computers whose last known parent was the Tier 0 or Domain Controllers OU as High Value
//
// The NOT ... CONTAINS guard below makes this idempotent (safe to re-run after every import):
// without it, re-running would append another "Tier0_Tombstone" to system_tags each time instead
// of a plain no-op on nodes already tagged.

MATCH (n)
WHERE (n:GhostHound_TombstoneUser OR n:GhostHound_TombstoneComputer OR n:GhostHound_TombstoneGroup)
  AND (n.lastknownparent CONTAINS "OU=Domain Controllers" OR n.lastknownparent CONTAINS "OU=Tier 0")
  AND NOT coalesce(n.system_tags, "") CONTAINS "Tier0_Tombstone"
SET n.system_tags = coalesce(n.system_tags, "") + " Tier0_Tombstone", n.highvalue = true
RETURN count(n) as TaggedTombstones
