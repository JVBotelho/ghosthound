#![forbid(unsafe_code)]

use ad_secdesc::SecurityDescriptor;
use ldap3::{Ldap, SearchEntry, SearchOptions, controls::RawControl};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum TombstoneError {
    #[error("LDAP error: {0}")]
    Ldap(#[from] ldap3::LdapError),
    #[error("Missing required attribute: {0}")]
    MissingAttribute(&'static str),
    #[error("operation timed out after {0}s (no response from the DC)")]
    Timeout(u64),
}

/// Wraps an LDAP round-trip with a client-side timeout.
///
/// `SearchOptions::timelimit` (set alongside this on every search below) is a *server-side*
/// hint the DC may honor or ignore, and its own docs say it does not cover "a network timeout
/// for retrieving result entries or the result of the whole operation." Against a wrong
/// `--dc-ip`, a firewalled port, or a dead link, that leaves nothing to stop the future from
/// hanging forever. This helper is the actual protection: every LDAP call in this crate goes
/// through it rather than relying on `timelimit` alone.
pub async fn with_timeout<T>(
    secs: u64,
    fut: impl Future<Output = Result<T, ldap3::LdapError>>,
) -> Result<T, TombstoneError> {
    match tokio::time::timeout(Duration::from_secs(secs), fut).await {
        Ok(inner) => inner.map_err(TombstoneError::from),
        Err(_) => Err(TombstoneError::Timeout(secs)),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TombstoneObject {
    pub object_guid: String,
    pub object_sid: Option<String>,
    pub dn: String,
    pub object_class: Vec<String>,
    pub is_deleted: bool,
    pub is_recycled: bool,
    pub recycle_bin_enabled: bool,
    pub group_membership_recoverable: bool,
    pub lastknownparent: Option<String>,
    pub member_of: Vec<String>,
}

impl TombstoneObject {
    pub fn from_entry(
        entry: &SearchEntry,
        recycle_bin_enabled: bool,
    ) -> Result<Self, TombstoneError> {
        let object_guid = entry
            .bin_attrs
            .get("objectGUID")
            .and_then(|v| v.first())
            .map(|bytes| {
                if bytes.len() == 16 {
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(bytes);
                    Uuid::from_bytes_le(arr).to_string()
                } else {
                    String::new()
                }
            })
            .unwrap_or_default();

        let dn = entry.dn.clone();

        let object_class = entry.attrs.get("objectClass").cloned().unwrap_or_default();

        let is_deleted = entry
            .attrs
            .get("isDeleted")
            .and_then(|v| v.first())
            .map(|s| s.eq_ignore_ascii_case("TRUE"))
            .unwrap_or(false);

        let is_recycled = entry
            .attrs
            .get("isRecycled")
            .and_then(|v| v.first())
            .map(|s| s.eq_ignore_ascii_case("TRUE"))
            .unwrap_or(false);

        let group_membership_recoverable = recycle_bin_enabled && !is_recycled;

        let lastknownparent = entry
            .attrs
            .get("lastKnownParent")
            .and_then(|v| v.first())
            .cloned();

        // AD strips linked-value attributes like memberOf once an object reaches the fully
        // stripped "Recycled" state; while still "Deleted" (recycle_bin_enabled && !is_recycled)
        // the value is retained on disk, which is what `group_membership_recoverable` reflects --
        // but even then, plain SHOW_DELETED doesn't surface it in a search: AD treats a link with
        // one deleted endpoint as "deactivated" and hides it unless the caller also passes
        // SHOW_DEACTIVATED_LINK (see fetch_tombstones), which is what actually makes this
        // non-empty in practice.
        let member_of = entry.attrs.get("memberOf").cloned().unwrap_or_default();

        let object_sid = entry
            .bin_attrs
            .get("objectSid")
            .and_then(|v| v.first())
            .and_then(|bytes| {
                let mut cursor = std::io::Cursor::new(bytes.as_slice());
                ad_secdesc::Sid::parse(&mut cursor).ok()
            })
            .map(|sid| sid.to_string());

        Ok(Self {
            object_guid,
            object_sid,
            dn,
            object_class,
            is_deleted,
            is_recycled,
            recycle_bin_enabled,
            group_membership_recoverable,
            lastknownparent,
            member_of,
        })
    }
}

/// Resolves a live object's `objectSid` from its DN. Used to turn a tombstone's preserved
/// `memberOf` (a list of group DNs) into SIDs so the graph can link back to those (still-live)
/// group nodes -- BloodHound edges match nodes by ID, not DN.
///
/// This intentionally uses a plain `match_by: "id"` reference rather than resolving the
/// group's BloodHound base kind (Group/User/Computer) and using `match_by: "property"`: BloodHound's
/// OpenGraph ingest scopes relationship-endpoint node identity to the ingest's own source kind
/// (`GhostHound` here) regardless of match strategy, so declaring the endpoint as kind `Group`
/// causes ingest to try creating a second `:Group` node with the same `objectid` -- which fails
/// outright on BloodHound's own uniqueness constraint (verified against a live instance). A plain
/// `match_by: "id"` reference creates a harmless placeholder node sharing the same `objectid`
/// instead of erroring; `bridge_shadow_nodes.cypher` links it to the real node afterward. See
/// docs/adr/0006-opengraph-cross-source-node-identity.md.
pub async fn resolve_object_sid(
    ldap: &mut Ldap,
    dn: &str,
    timeout_secs: u64,
) -> Result<Option<String>, TombstoneError> {
    let opts = SearchOptions::new().timelimit(timeout_secs as i32);
    let (rs, _) = with_timeout(
        timeout_secs,
        ldap.with_search_options(opts).search(
            dn,
            ldap3::Scope::Base,
            "(objectClass=*)",
            vec!["objectSid"],
        ),
    )
    .await?
    .success()?;

    Ok(rs.into_iter().find_map(|entry| {
        let search_entry = SearchEntry::construct(entry);
        search_entry
            .bin_attrs
            .get("objectSid")
            .and_then(|v| v.first())
            .and_then(|bytes| {
                let mut cursor = std::io::Cursor::new(bytes.as_slice());
                ad_secdesc::Sid::parse(&mut cursor).ok()
            })
            .map(|sid| sid.to_string())
    }))
}

pub async fn check_recycle_bin_enabled(
    ldap: &mut Ldap,
    timeout_secs: u64,
) -> Result<bool, TombstoneError> {
    // 1. Get Configuration Naming Context from RootDSE
    let opts = SearchOptions::new().timelimit(timeout_secs as i32);
    let (rs_root, _) = with_timeout(
        timeout_secs,
        ldap.with_search_options(opts.clone()).search(
            "",
            ldap3::Scope::Base,
            "(objectClass=*)",
            vec!["configurationNamingContext"],
        ),
    )
    .await?
    .success()?;

    let config_nc = if let Some(entry) = rs_root.first() {
        let search_entry = SearchEntry::construct(entry.clone());
        search_entry
            .attrs
            .get("configurationNamingContext")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default()
    } else {
        return Ok(false);
    };

    if config_nc.is_empty() {
        return Ok(false);
    }

    // 2. Search Partitions container for msDS-EnabledFeature
    let partitions_dn = format!("CN=Partitions,{}", config_nc);
    let (rs_part, _) = with_timeout(
        timeout_secs,
        ldap.with_search_options(opts).search(
            &partitions_dn,
            ldap3::Scope::Base,
            "(objectClass=*)",
            vec!["msDS-EnabledFeature"],
        ),
    )
    .await?
    .success()?;

    for entry in rs_part {
        let search_entry = SearchEntry::construct(entry);
        if let Some(features) = search_entry.attrs.get("msDS-EnabledFeature") {
            for feature in features {
                if feature.contains("Recycle Bin Feature")
                    || feature.contains("766ddcd8-acd0-445e-f3b9-a7f9b6744f2a")
                {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

/// Whether an ACE type actually *grants* access. MS-DTYP defines deny (0x01/0x06/0x0A/0x0C),
/// audit/alarm (0x02/0x03/0x07/0x08/0x0D/0x0F), and other non-granting ACE types alongside the
/// allow types below -- all of which can carry the same access_mask bits and object_type GUID as
/// a real grant, so ace_type must be checked explicitly rather than inferred from the mask alone.
fn is_allow_ace(ace_type: u8) -> bool {
    matches!(ace_type, 0x00 | 0x05 | 0x09 | 0x0B)
}

/// Whether an ACE actually applies to the object it's read from, as opposed to only propagating
/// to children (INHERIT_ONLY_ACE, 0x08). The Reanimate-Tombstones right is evaluated at the
/// domain NC root itself, so an inherit-only ACE there doesn't grant anything on that object.
fn applies_to_self(ace_flags: u8) -> bool {
    ace_flags & 0x08 == 0
}

pub async fn check_reanimate_rights(
    ldap: &mut Ldap,
    domain_nc: &str,
    timeout_secs: u64,
) -> Result<Vec<String>, TombstoneError> {
    // Read nTSecurityDescriptor from the domain naming context root itself (not
    // CN=Deleted Objects): the Reanimate-Tombstones control access right is evaluated at the
    // NC root, so that DACL is the one that matters (see docs/adr/0001). The SHOW_DELETED
    // control is harmless but unnecessary here since domain_nc is a live, non-deleted object;
    // it's included only for consistency with the other searches in this crate.
    let ctrl = RawControl {
        ctype: "1.2.840.113556.1.4.417".to_string(),
        crit: true,
        val: None,
    };

    let opts = SearchOptions::new().timelimit(timeout_secs as i32);
    let (rs, _) = with_timeout(
        timeout_secs,
        ldap.with_controls(ctrl).with_search_options(opts).search(
            domain_nc,
            ldap3::Scope::Base,
            "(objectClass=*)",
            vec!["nTSecurityDescriptor"],
        ),
    )
    .await?
    .success()?;

    let mut principals = Vec::new();
    let reanimate_guid = Uuid::parse_str("45ec5156-db7e-47bb-b53f-dbeb2d03c40f").unwrap();

    for entry in rs {
        let search_entry = SearchEntry::construct(entry);
        if let Some(sec_desc_bytes) = search_entry
            .bin_attrs
            .get("nTSecurityDescriptor")
            .and_then(|v| v.first())
            && let Ok(sd) = SecurityDescriptor::parse(sec_desc_bytes)
            && let Some(dacl) = sd.dacl
        {
            for ace in dacl.aces {
                // Grants a control access right (ExtendedRight 0x100, or GenericAll 0x10000000)
                // AND that right is either unscoped (non-object ACE, which implicitly grants
                // all control access rights per AD semantics) or scoped to exactly the
                // Reanimate-Tombstones GUID -- but only if the ACE is an actual grant (not a
                // deny/audit ACE reusing the same mask/GUID) that applies to this object itself
                // (not inherit-only).
                let grants_control_access =
                    (ace.access_mask & 0x00000100 != 0) || (ace.access_mask & 0x10000000 != 0);
                let is_reanimate_right =
                    ace.object_type == Some(reanimate_guid) || ace.object_type.is_none();
                if grants_control_access
                    && is_reanimate_right
                    && is_allow_ace(ace.ace_type)
                    && applies_to_self(ace.ace_flags)
                {
                    principals.push(ace.sid.to_string());
                }
            }
        }
    }

    // A principal can hold the right via more than one qualifying ACE (e.g. both an unscoped
    // GenericAll grant and a scoped ExtendedRight grant); dedup so callers don't emit one
    // CanReanimate edge per matching ACE for the same SID.
    principals.sort_unstable();
    principals.dedup();

    Ok(principals)
}

pub async fn fetch_tombstones(
    ldap: &mut Ldap,
    domain_nc: &str,
    recycle_bin_enabled: bool,
    timeout_secs: u64,
) -> Result<Vec<TombstoneObject>, TombstoneError> {
    let deleted_objects_dn = format!("CN=Deleted Objects,{}", domain_nc);

    // SHOW_DELETED surfaces the tombstone itself as a search result. On its own, though, AD
    // still hides the tombstone's own linked-value attributes (memberOf here) because the link
    // is considered "deactivated" once one endpoint is deleted -- SHOW_DEACTIVATED_LINK is what
    // makes those values visible again, which is what lets us see (and later graph) the groups
    // this tombstone used to belong to.
    let ctrls = vec![
        RawControl {
            ctype: "1.2.840.113556.1.4.417".to_string(),
            crit: true,
            val: None,
        },
        RawControl {
            ctype: "1.2.840.113556.1.4.2065".to_string(),
            crit: true,
            val: None,
        },
    ];

    let opts = SearchOptions::new().timelimit(timeout_secs as i32);
    let (rs, _) = with_timeout(
        timeout_secs,
        ldap.with_controls(ctrls).with_search_options(opts).search(
            &deleted_objects_dn,
            ldap3::Scope::Subtree,
            "(isDeleted=*)",
            vec![
                "objectGUID",
                "objectSid",
                "objectClass",
                "isDeleted",
                "isRecycled",
                "lastKnownParent",
                "memberOf",
            ],
        ),
    )
    .await?
    .success()?;

    let mut tombstones = Vec::new();
    for entry in rs {
        let search_entry = SearchEntry::construct(entry);
        // Exclude the container itself
        if search_entry.dn.eq_ignore_ascii_case(&deleted_objects_dn) {
            continue;
        }
        if let Ok(tombstone) = TombstoneObject::from_entry(&search_entry, recycle_bin_enabled) {
            tombstones.push(tombstone);
        }
    }

    Ok(tombstones)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ldap3::SearchEntry;
    use std::collections::HashMap;

    #[test]
    fn test_is_allow_ace() {
        assert!(is_allow_ace(0x00)); // ACCESS_ALLOWED_ACE_TYPE
        assert!(is_allow_ace(0x05)); // ACCESS_ALLOWED_OBJECT_ACE_TYPE
        assert!(is_allow_ace(0x09)); // ACCESS_ALLOWED_CALLBACK_ACE_TYPE
        assert!(is_allow_ace(0x0B)); // ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
        assert!(!is_allow_ace(0x01)); // ACCESS_DENIED_ACE_TYPE
        assert!(!is_allow_ace(0x06)); // ACCESS_DENIED_OBJECT_ACE_TYPE
        assert!(!is_allow_ace(0x07)); // SYSTEM_AUDIT_OBJECT_ACE_TYPE
        assert!(!is_allow_ace(0x0A)); // ACCESS_DENIED_CALLBACK_ACE_TYPE
        assert!(!is_allow_ace(0x0C)); // ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
    }

    #[test]
    fn test_applies_to_self() {
        assert!(applies_to_self(0x00));
        assert!(!applies_to_self(0x08)); // INHERIT_ONLY_ACE
        assert!(!applies_to_self(0x0A)); // INHERIT_ONLY_ACE | CONTAINER_INHERIT_ACE
    }

    #[test]
    fn test_tombstone_from_entry_recycled() {
        let mut attrs = HashMap::new();
        attrs.insert(
            "objectClass".to_string(),
            vec!["user".to_string(), "person".to_string()],
        );
        attrs.insert("isDeleted".to_string(), vec!["TRUE".to_string()]);
        attrs.insert("isRecycled".to_string(), vec!["TRUE".to_string()]);
        attrs.insert(
            "lastKnownParent".to_string(),
            vec!["CN=Users,DC=ghost,DC=local".to_string()],
        );

        let mut bin_attrs = HashMap::new();
        // Mock GUID
        bin_attrs.insert("objectGUID".to_string(), vec![vec![0; 16]]);

        let entry = SearchEntry {
            dn: "CN=DeletedUser\\0ADEL:guid,CN=Deleted Objects,DC=ghost,DC=local".to_string(),
            attrs,
            bin_attrs,
        };

        // If recycle bin is enabled but the object is marked isRecycled=TRUE,
        // group membership is NOT recoverable.
        let tombstone = TombstoneObject::from_entry(&entry, true).unwrap();
        assert!(tombstone.is_deleted);
        assert!(tombstone.is_recycled);
        assert!(!tombstone.group_membership_recoverable);
        assert_eq!(tombstone.object_class, vec!["user", "person"]);
        assert_eq!(
            tombstone.lastknownparent,
            Some("CN=Users,DC=ghost,DC=local".to_string())
        );
    }

    #[test]
    fn test_tombstone_from_entry_preserves_member_of() {
        let mut attrs = HashMap::new();
        attrs.insert("isDeleted".to_string(), vec!["TRUE".to_string()]);
        attrs.insert(
            "memberOf".to_string(),
            vec!["CN=Domain Admins,CN=Users,DC=ghost,DC=local".to_string()],
        );

        let mut bin_attrs = HashMap::new();
        bin_attrs.insert("objectGUID".to_string(), vec![vec![0; 16]]);

        let entry = SearchEntry {
            dn: "CN=RecoverableAdmin,CN=Deleted Objects,DC=ghost,DC=local".to_string(),
            attrs,
            bin_attrs,
        };

        let tombstone = TombstoneObject::from_entry(&entry, true).unwrap();
        assert!(tombstone.group_membership_recoverable);
        assert_eq!(
            tombstone.member_of,
            vec!["CN=Domain Admins,CN=Users,DC=ghost,DC=local".to_string()]
        );
    }

    #[test]
    fn test_tombstone_from_entry_recoverable() {
        let mut attrs = HashMap::new();
        attrs.insert("isDeleted".to_string(), vec!["TRUE".to_string()]);
        // isRecycled not present or FALSE

        let mut bin_attrs = HashMap::new();
        bin_attrs.insert("objectGUID".to_string(), vec![vec![0; 16]]);

        let entry = SearchEntry {
            dn: "CN=RecoverableUser,CN=Deleted Objects,DC=ghost,DC=local".to_string(),
            attrs,
            bin_attrs,
        };

        let tombstone = TombstoneObject::from_entry(&entry, true).unwrap();
        assert!(tombstone.is_deleted);
        assert!(!tombstone.is_recycled);
        assert!(tombstone.group_membership_recoverable);
    }
}
