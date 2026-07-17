//! Active Directory tombstone/Recycle Bin enumeration and reanimation-rights analysis over LDAP.
//!
//! This is the domain-logic layer behind
//! [GhostHound](https://github.com/JVBotelho/ghosthound)'s tombstone-reanimation attack-path
//! analysis: it enumerates tombstones, models their AD Recycle Bin state, and determines who
//! holds the Reanimate-Tombstones right. It's a plain library with no CLI or OpenGraph output of
//! its own -- see the `ghosthound` crate for that.
//!
//! Typical flow, given an authenticated [`ldap3::Ldap`] handle and a domain naming context:
//! [`check_recycle_bin_enabled`], then [`fetch_tombstones`] and [`check_reanimate_rights`]. See
//! this crate's README for a full usage example.

#![forbid(unsafe_code)]

use ad_secdesc::SecurityDescriptor;
use ldap3::{Ldap, SearchEntry, SearchOptions, adapters::PagedResults, controls::RawControl};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;

/// AD's own default `MaxPageSize` LDAP policy limit. Requesting exactly this many entries per
/// page keeps `fetch_tombstones` aligned with what a default-configured DC already enforces,
/// rather than picking an arbitrary smaller number.
const LDAP_PAGE_SIZE: i32 = 1000;

/// Errors returned while enumerating tombstones or reanimation rights over LDAP.
#[derive(Error, Debug)]
pub enum TombstoneError {
    /// An LDAP protocol/connection error, passed through from `ldap3`.
    #[error("LDAP error: {0}")]
    Ldap(#[from] ldap3::LdapError),
    /// An expected attribute was missing from a search result.
    #[error("Missing required attribute: {0}")]
    MissingAttribute(&'static str),
    /// The operation didn't complete within the configured timeout -- see [`with_timeout`] for
    /// why this exists.
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

/// A deleted AD object (a "tombstone"), enumerated from `CN=Deleted Objects` via
/// [`fetch_tombstones`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TombstoneObject {
    /// The object's `objectGUID`, formatted as a standard UUID string. Empty if the raw
    /// attribute value wasn't exactly 16 bytes.
    pub object_guid: String,
    /// The object's `objectSid`, formatted as an `S-1-5-...` string, if present (not every
    /// tombstoned object class has one).
    pub object_sid: Option<String>,
    /// The tombstone's current distinguished name (under `CN=Deleted Objects`).
    pub dn: String,
    /// The object's `objectClass` values (e.g. `["top", "person", "organizationalPerson",
    /// "user"]`).
    pub object_class: Vec<String>,
    /// Always `true` for anything `fetch_tombstones` returns (it filters on `isDeleted=*`);
    /// kept as a field since it's read directly off the LDAP response.
    pub is_deleted: bool,
    /// Whether the object has reached the fully-stripped "Recycled" state. `false` means it's
    /// still in the full-fidelity "Deleted" state (see `group_membership_recoverable`).
    pub is_recycled: bool,
    /// Whether the domain has the AD Recycle Bin optional feature enabled at all (the same value
    /// for every tombstone in a given enumeration run, from [`check_recycle_bin_enabled`]).
    pub recycle_bin_enabled: bool,
    /// Derived: `recycle_bin_enabled && !is_recycled`. When `true`, this tombstone's group
    /// memberships (see `member_of`) are still intact and would be restored along with it.
    pub group_membership_recoverable: bool,
    /// The DN of the object's parent container before deletion, if AD recorded one.
    pub lastknownparent: Option<String>,
    /// DNs of groups this object belonged to, preserved only while `group_membership_recoverable`
    /// is `true`. Reading this at all requires the `SHOW_DEACTIVATED_LINK` LDAP control in
    /// addition to `SHOW_DELETED` -- see [`fetch_tombstones`].
    pub member_of: Vec<String>,
    /// The object's `sAMAccountName`, if AD still has it. Unlike `member_of`, this is a plain
    /// (non-linked-value) attribute, so it's visible under plain `SHOW_DELETED` without needing
    /// `SHOW_DEACTIVATED_LINK` -- it's preserved on disk the same way other core attributes are
    /// while the object is in the "Deleted" state, and stripped once fully "Recycled". Used as
    /// the node's display name -- without it, a tombstone shows up in BloodHound as a bare
    /// SID/GUID string.
    pub sam_account_name: Option<String>,
}

impl TombstoneObject {
    /// Builds a [`TombstoneObject`] from a raw LDAP search result entry.
    ///
    /// `recycle_bin_enabled` must come from a separate [`check_recycle_bin_enabled`] call (it's
    /// a domain-wide setting, not something readable off the tombstone entry itself).
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

        let sam_account_name = entry
            .attrs
            .get("sAMAccountName")
            .and_then(|v| v.first())
            .cloned();

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
            sam_account_name,
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

/// Checks whether the domain has the AD Recycle Bin optional feature enabled, by looking up
/// `msDS-EnabledFeature` under `CN=Partitions` in the configuration naming context (found via a
/// RootDSE lookup first).
///
/// This is domain-wide state, not something readable off any individual tombstone -- call it
/// once per run and pass the result to [`fetch_tombstones`]/[`TombstoneObject::from_entry`].
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

    // An empty/missing RootDSE response here means the query itself came back empty -- almost
    // certainly a connectivity or permissions problem, not a legitimate "Recycle Bin is
    // disabled" answer. Treat it as an error rather than silently reporting `false`, so a
    // broken lookup can't be misread as a confirmed-disabled Recycle Bin.
    let config_nc = if let Some(entry) = rs_root.first() {
        let search_entry = SearchEntry::construct(entry.clone());
        search_entry
            .attrs
            .get("configurationNamingContext")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default()
    } else {
        return Err(TombstoneError::MissingAttribute(
            "configurationNamingContext",
        ));
    };

    if config_nc.is_empty() {
        return Err(TombstoneError::MissingAttribute(
            "configurationNamingContext",
        ));
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

/// Returns the SIDs (as `S-1-5-...` strings, deduplicated) of every principal holding the
/// Reanimate-Tombstones right on the domain.
///
/// Reads and parses `nTSecurityDescriptor` from `domain_nc` itself -- the right is evaluated at
/// the domain naming-context root, not on `CN=Deleted Objects` or on individual tombstones -- and
/// only counts ACEs that actually grant it (correctly excluding deny/audit ACEs and
/// inherit-only ACEs that happen to carry the same access mask or object-type GUID).
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

/// Enumerates every tombstone under `CN=Deleted Objects,<domain_nc>`.
///
/// Uses both the `SHOW_DELETED` control (to see the tombstones at all) and
/// `SHOW_DEACTIVATED_LINK` (to see their preserved `memberOf` values, if any -- see
/// [`TombstoneObject::member_of`]). Pass the same `recycle_bin_enabled` value obtained from
/// [`check_recycle_bin_enabled`] earlier in the run.
///
/// Paged with the Simple Paged Results control (page size [`LDAP_PAGE_SIZE`]) rather than a
/// single unpaged search: AD's default `MaxPageSize` policy caps an unpaged search at 1000
/// entries, so any domain with more tombstones than that would otherwise fail outright with
/// `sizeLimitExceeded` instead of silently truncating.
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
    let mut stream = ldap
        .with_controls(ctrls)
        .with_search_options(opts)
        .streaming_search_with(
            PagedResults::new(LDAP_PAGE_SIZE),
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
                "sAMAccountName",
            ],
        )
        .await?;

    let mut tombstones = Vec::new();
    while let Some(entry) = with_timeout(timeout_secs, stream.next()).await? {
        let search_entry = SearchEntry::construct(entry);
        // Exclude the container itself
        if search_entry.dn.eq_ignore_ascii_case(&deleted_objects_dn) {
            continue;
        }
        if let Ok(tombstone) = TombstoneObject::from_entry(&search_entry, recycle_bin_enabled) {
            tombstones.push(tombstone);
        }
    }
    stream.finish().await.success()?;

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

    #[test]
    fn test_tombstone_from_entry_sam_account_name() {
        let mut attrs = HashMap::new();
        attrs.insert("isDeleted".to_string(), vec!["TRUE".to_string()]);
        attrs.insert("sAMAccountName".to_string(), vec!["svc-test".to_string()]);

        let mut bin_attrs = HashMap::new();
        bin_attrs.insert("objectGUID".to_string(), vec![vec![0; 16]]);

        let entry = SearchEntry {
            dn: "CN=svc-test,CN=Deleted Objects,DC=ghost,DC=local".to_string(),
            attrs,
            bin_attrs,
        };

        let tombstone = TombstoneObject::from_entry(&entry, true).unwrap();
        assert_eq!(tombstone.sam_account_name, Some("svc-test".to_string()));
    }

    #[test]
    fn test_tombstone_from_entry_missing_sam_account_name() {
        let mut attrs = HashMap::new();
        attrs.insert("isDeleted".to_string(), vec!["TRUE".to_string()]);

        let mut bin_attrs = HashMap::new();
        bin_attrs.insert("objectGUID".to_string(), vec![vec![0; 16]]);

        let entry = SearchEntry {
            dn: "CN=stripped,CN=Deleted Objects,DC=ghost,DC=local".to_string(),
            attrs,
            bin_attrs,
        };

        let tombstone = TombstoneObject::from_entry(&entry, true).unwrap();
        assert_eq!(tombstone.sam_account_name, None);
    }
}
