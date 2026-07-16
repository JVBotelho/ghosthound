// Privilege Zone Rule for High-Value Tombstones
// Marks Tombstone users/computers whose last known parent was the Tier 0 or Domain Controllers OU as High Value

MATCH (n)
WHERE (n:TombstoneUser OR n:TombstoneComputer OR n:TombstoneGroup)
  AND (n.lastknownparent CONTAINS "OU=Domain Controllers" OR n.lastknownparent CONTAINS "OU=Tier 0")
SET n.system_tags = coalesce(n.system_tags, "") + " Tier0_Tombstone", n.highvalue = true
RETURN count(n) as TaggedTombstones
