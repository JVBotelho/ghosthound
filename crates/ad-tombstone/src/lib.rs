#![forbid(unsafe_code)]

use ad_secdesc::SecurityDescriptor;
use ldap3::{Ldap, SearchEntry, controls::RawControl};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum TombstoneError {
    #[error("LDAP error: {0}")]
    Ldap(#[from] ldap3::LdapError),
    #[error("Missing required attribute: {0}")]
    MissingAttribute(&'static str),
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
        })
    }
}

pub async fn check_recycle_bin_enabled(ldap: &mut Ldap) -> Result<bool, TombstoneError> {
    // 1. Get Configuration Naming Context from RootDSE
    let (rs_root, _) = ldap
        .search(
            "",
            ldap3::Scope::Base,
            "(objectClass=*)",
            vec!["configurationNamingContext"],
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
    let (rs_part, _) = ldap
        .search(
            &partitions_dn,
            ldap3::Scope::Base,
            "(objectClass=*)",
            vec!["msDS-EnabledFeature"],
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

pub async fn check_reanimate_rights(
    ldap: &mut Ldap,
    domain_nc: &str,
) -> Result<Vec<String>, TombstoneError> {
    // Use SHOW_DELETED control to read the hidden container
    let ctrl = RawControl {
        ctype: "1.2.840.113556.1.4.417".to_string(),
        crit: true,
        val: None,
    };

    let (rs, _) = ldap
        .with_controls(ctrl)
        .search(
            domain_nc,
            ldap3::Scope::Base,
            "(objectClass=*)",
            vec!["nTSecurityDescriptor"],
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
                // Reanimate-Tombstones GUID.
                let grants_control_access =
                    (ace.access_mask & 0x00000100 != 0) || (ace.access_mask & 0x10000000 != 0);
                let is_reanimate_right =
                    ace.object_type == Some(reanimate_guid) || ace.object_type.is_none();
                if grants_control_access && is_reanimate_right {
                    principals.push(ace.sid.to_string());
                }
            }
        }
    }

    Ok(principals)
}

pub async fn fetch_tombstones(
    ldap: &mut Ldap,
    domain_nc: &str,
    recycle_bin_enabled: bool,
) -> Result<Vec<TombstoneObject>, TombstoneError> {
    let deleted_objects_dn = format!("CN=Deleted Objects,{}", domain_nc);

    let ctrl = RawControl {
        ctype: "1.2.840.113556.1.4.417".to_string(),
        crit: true,
        val: None,
    };

    let (rs, _) = ldap
        .with_controls(ctrl)
        .search(
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
            ],
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
