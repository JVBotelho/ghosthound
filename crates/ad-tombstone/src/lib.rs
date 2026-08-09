//! Active Directory tombstone/Recycle Bin enumeration and reanimation-rights analysis over LDAP.
//!
//! This is the domain-logic layer behind
//! [GhostHound](https://github.com/JVBotelho/ghosthound)'s tombstone-reanimation attack-path
//! analysis: it enumerates tombstones, models their AD Recycle Bin state, and determines who can
//! reanimate them. It's a plain library with no CLI or OpenGraph output of its own -- see the
//! `ghosthound` crate for that.
//!
//! Reanimation control comes from two places, and both are collected:
//!
//! - the **Reanimate-Tombstones** control access right, held domain-wide and read off the domain
//!   naming-context root -- [`check_reanimate_rights`];
//! - **ownership or `WRITE_DAC`/`WRITE_OWNER` on an individual tombstone**, which lets a principal
//!   rewrite that object's DACL and grant itself the right -- [`TombstoneObject::owner_sid`] and
//!   [`TombstoneObject::reanimation_paths`], computed by [`analyze_reanimation_control`].
//!
//! Typical flow, given an authenticated [`ldap3::Ldap`] handle and a domain naming context:
//! [`check_recycle_bin_enabled`], then [`fetch_tombstones`] and [`check_reanimate_rights`]. See
//! this crate's README for a full usage example.

#![forbid(unsafe_code)]

use ad_secdesc::{Ace, SecurityDescriptor};
use ldap3::{Ldap, SearchEntry, SearchOptions, adapters::PagedResults, controls::RawControl};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;

/// AD's own default `MaxPageSize` LDAP policy limit. Requesting exactly this many entries per
/// page keeps `fetch_tombstones` aligned with what a default-configured DC already enforces,
/// rather than picking an arbitrary smaller number.
const LDAP_PAGE_SIZE: i32 = 1000;

/// `ADS_RIGHT_DS_CONTROL_ACCESS` -- the right to exercise a control access (extended) right, such
/// as Reanimate-Tombstones.
const RIGHT_DS_CONTROL_ACCESS: u32 = 0x0000_0100;

/// `ADS_RIGHT_GENERIC_ALL` -- implies every other right, including all control access rights.
const RIGHT_GENERIC_ALL: u32 = 0x1000_0000;

/// `WRITE_DAC` -- the right to rewrite the object's DACL, and therefore to grant oneself any
/// right on it (including Reanimate-Tombstones).
const RIGHT_WRITE_DAC: u32 = 0x0004_0000;

/// `WRITE_OWNER` -- the right to take ownership of the object, which in turn confers `WRITE_DAC`.
const RIGHT_WRITE_OWNER: u32 = 0x0008_0000;

/// `LDAP_SERVER_SD_FLAGS_OID` -- restricts which parts of `nTSecurityDescriptor` the DC returns.
///
/// This control is **mandatory, not an optimization**, for any bind that isn't
/// `SeSecurityPrivilege`-holding. Without it AD tries to return the *entire* descriptor including
/// the SACL; reading a SACL requires that privilege, and rather than returning the readable parts,
/// the DC **omits `nTSecurityDescriptor` from the response entirely**. The attribute silently
/// disappears and every DACL/owner-based finding with it -- which is exactly what happened
/// enumerating as a plain user before this was added.
const SD_FLAGS_CONTROL_OID: &str = "1.2.840.113556.1.4.801";

/// BER-encoded control value for [`SD_FLAGS_CONTROL_OID`]: `SEQUENCE { INTEGER 0x07 }`, i.e.
/// `OWNER (0x1) | GROUP (0x2) | DACL (0x4)` -- everything this crate reads, and nothing that needs
/// a privilege a normal enumerating account won't have. `SACL (0x8)` is deliberately excluded.
const SD_FLAGS_OWNER_GROUP_DACL: [u8; 5] = [0x30, 0x03, 0x02, 0x01, 0x07];

/// The `LDAP_SERVER_SD_FLAGS_OID` control asking for owner + group + DACL only.
///
/// Sent non-critical: on a DC that somehow doesn't implement the control, the search still returns
/// (degrading to the old "descriptor omitted" behavior, which callers already report) instead of
/// failing outright.
fn sd_flags_control() -> RawControl {
    RawControl {
        ctype: SD_FLAGS_CONTROL_OID.to_string(),
        crit: false,
        val: Some(SD_FLAGS_OWNER_GROUP_DACL.to_vec()),
    }
}

/// The Reanimate-Tombstones control access right's `rightsGuid`.
///
/// Parsed at each use rather than stored as a `const`, matching how this crate already reads
/// GUIDs; the literal is fixed, so `expect` here is unreachable.
fn reanimate_tombstones_guid() -> Uuid {
    Uuid::parse_str("45ec5156-db7e-47bb-b53f-dbeb2d03c40f").expect("static GUID literal is valid")
}

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
    /// The `OwnerSid` of the tombstone's own `nTSecurityDescriptor`, if the descriptor was
    /// readable and parseable. `None` when the bound principal lacks `READ_CONTROL` on the
    /// tombstone (AD then omits the attribute entirely rather than erroring).
    ///
    /// The owner of an object can always rewrite its DACL, so this is a reanimation path in its
    /// own right -- see `reanimation_paths`.
    pub owner_sid: Option<String>,
    /// Every principal that can reanimate *this specific tombstone*, from its own
    /// `nTSecurityDescriptor` -- via ownership, `WRITE_DAC`/`WRITE_OWNER`, or an
    /// (often inherited) Reanimate-Tombstones ACE. Computed by
    /// [`analyze_reanimation_control`]; empty when the descriptor wasn't readable.
    ///
    /// Distinct from [`check_reanimate_rights`], which reads the *domain NC root* descriptor and
    /// so applies to every tombstone at once. Callers emit `CanReanimate` edges from the union of
    /// the two.
    pub reanimation_paths: Vec<ReanimationPath>,
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

        // A tombstone's own nTSecurityDescriptor carries both halves of the ownership/DACL
        // reanimation path: the OwnerSid, and any WRITE_DAC/WRITE_OWNER or (usually inherited from
        // CN=Deleted Objects) Reanimate-Tombstones ACE. A missing attribute means the bound
        // principal has no READ_CONTROL on this object; an unparseable one means a malformed blob.
        // Neither is fatal to enumerating the rest of the tombstone, so both degrade to "no
        // ownership/ACL data" rather than failing the whole object.
        let (owner_sid, reanimation_paths) = raw_attr(entry, "nTSecurityDescriptor")
            .and_then(|bytes| SecurityDescriptor::parse(&bytes).ok())
            .map(|sd| {
                let owner = sd.owner.as_ref().map(|s| s.to_string());
                (owner, analyze_reanimation_control(&sd))
            })
            .unwrap_or_default();

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
            owner_sid,
            reanimation_paths,
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
/// The same applies to a tombstone's own DACL: an ACE inherited *from* `CN=Deleted Objects` shows
/// up there with INHERITED_ACE (0x10) set but not INHERIT_ONLY_ACE, so it still counts.
fn applies_to_self(ace_flags: u8) -> bool {
    ace_flags & 0x08 == 0
}

/// How a principal ends up able to reanimate a given tombstone.
///
/// Variant order is significant: it's the precedence used by [`ReanimationPath::primary`] and by
/// `Ord`, running from "the right is already formally granted" to "the principal must rewrite the
/// object's security descriptor first". The two are operationally different -- the second needs an
/// extra ACL-rewrite step that is loud and auditable -- so the distinction is preserved on the
/// emitted edge rather than flattened away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReanimateMechanism {
    /// The principal holds the Reanimate-Tombstones control access right (or an unscoped
    /// control-access grant, which implies it).
    ReanimateRight,
    /// The principal is the object's owner (`OwnerSid`), and an owner can always rewrite the
    /// object's DACL regardless of what the DACL itself says.
    Owner,
    /// The principal holds `WRITE_DAC` on the object and can grant itself the right.
    WriteDac,
    /// The principal holds `WRITE_OWNER` on the object, can take ownership, and thereby obtain
    /// `WRITE_DAC`.
    WriteOwner,
}

impl ReanimateMechanism {
    /// The stable string used on emitted graph edges (`reanimate_right`, `owner`, `write_dac`,
    /// `write_owner`) -- what Cypher queries match on, so it must not change casually.
    pub fn as_str(&self) -> &'static str {
        match self {
            ReanimateMechanism::ReanimateRight => "reanimate_right",
            ReanimateMechanism::Owner => "owner",
            ReanimateMechanism::WriteDac => "write_dac",
            ReanimateMechanism::WriteOwner => "write_owner",
        }
    }
}

impl std::fmt::Display for ReanimateMechanism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One principal's ability to reanimate a tombstone, together with every mechanism that grants it.
///
/// One entry per SID, never one per qualifying ACE: a principal that is both the owner and holds
/// `WRITE_DAC` appears once with both mechanisms recorded, so callers emit a single edge (same
/// de-duplication rule [`check_reanimate_rights`] already applies to its SID list).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReanimationPath {
    /// The principal's SID, as an `S-1-5-...` string.
    pub sid: String,
    /// Every mechanism granting this principal control, in [`ReanimateMechanism`] precedence
    /// order, deduplicated. Never empty.
    pub mechanisms: Vec<ReanimateMechanism>,
}

impl ReanimationPath {
    /// The strongest (lowest-precedence-value) mechanism -- what to report as the edge's single
    /// `source` property when a query wants one value rather than the full list.
    pub fn primary(&self) -> ReanimateMechanism {
        // `mechanisms` is built from a BTreeSet and is documented non-empty; fall back to the
        // weakest mechanism rather than panicking if a hand-constructed value breaks that.
        self.mechanisms
            .first()
            .copied()
            .unwrap_or(ReanimateMechanism::WriteOwner)
    }
}

/// Whether this ACE grants the Reanimate-Tombstones right **as read at the domain NC root**.
///
/// Either an unscoped grant (no `object_type`, which per AD semantics covers every control access
/// right the mask allows) or one scoped to exactly the Reanimate-Tombstones GUID. `GenericAll`
/// counts too, since it implies all control access rights.
///
/// This is the NC-root rule only, and must not be applied to an individual object's descriptor --
/// see `grants_reanimate_right_on_object` for why the two differ.
///
/// Does **not** check `ace_type`/`ace_flags` -- callers must gate on `is_allow_ace` and
/// `applies_to_self` first.
fn grants_reanimate_right_at_nc_root(ace: &Ace) -> bool {
    let grants_control_access =
        ace.access_mask & (RIGHT_DS_CONTROL_ACCESS | RIGHT_GENERIC_ALL) != 0;
    let is_reanimate_right =
        ace.object_type == Some(reanimate_tombstones_guid()) || ace.object_type.is_none();
    grants_control_access && is_reanimate_right
}

/// Whether this ACE, read from an **individual object's** descriptor, grants the
/// Reanimate-Tombstones right -- which requires the ACE to name that right's GUID explicitly.
///
/// Deliberately stricter than `grants_reanimate_right_at_nc_root`. Reanimate-Tombstones is a
/// control access right validated at the domain naming-context root (ADR-0001), so an *unscoped*
/// control-access grant -- or `GenericAll` -- on a tombstone does **not** confer it: it confers
/// broad write access to that one object, which is a `write_dac`/`write_owner`-class finding
/// requiring an ACL rewrite first, not a formally-held right. Reporting such an ACE as
/// `reanimate_right` overstates it, which is the whole distinction the mechanism labels exist to
/// draw.
///
/// A genuine object-level grant does occur -- typically an ACE inherited from `CN=Deleted Objects`
/// naming the GUID -- and that is exactly what this matches.
///
/// Does **not** check `ace_type`/`ace_flags` -- callers must gate on `is_allow_ace` and
/// `applies_to_self` first.
fn grants_reanimate_right_on_object(ace: &Ace) -> bool {
    let grants_control_access =
        ace.access_mask & (RIGHT_DS_CONTROL_ACCESS | RIGHT_GENERIC_ALL) != 0;
    grants_control_access && ace.object_type == Some(reanimate_tombstones_guid())
}

/// Whether this ACE grants `WRITE_DAC` or `WRITE_OWNER` on the object, i.e. lets the trustee
/// rewrite the security descriptor and grant itself the Reanimate-Tombstones right.
///
/// `GenericAll` counts for both: the generic-to-specific mapping expands it to every standard
/// right, `WRITE_DAC` and `WRITE_OWNER` included. On an individual object that is precisely what a
/// `GenericAll` ACE buys -- the ability to rewrite the descriptor -- not the formal extended right
/// (see `grants_reanimate_right_on_object`).
///
/// `object_type` is deliberately ignored: it only narrows the AD-specific rights (control-access,
/// read/write-property, create/delete-child), never the standard rights `WRITE_DAC`/`WRITE_OWNER`,
/// which always apply to the object as a whole. `GENERIC_WRITE` is *not* included -- for a directory
/// object it maps to write-property/self, which does not include `WRITE_DAC`.
///
/// Does **not** check `ace_type`/`ace_flags` -- callers must gate on `is_allow_ace` and
/// `applies_to_self` first.
fn grants_secdesc_write(ace: &Ace) -> (bool, bool) {
    (
        ace.access_mask & (RIGHT_WRITE_DAC | RIGHT_GENERIC_ALL) != 0,
        ace.access_mask & (RIGHT_WRITE_OWNER | RIGHT_GENERIC_ALL) != 0,
    )
}

/// Analyzes one object's security descriptor for every principal that can reanimate it, by any of
/// the mechanisms in [`ReanimateMechanism`].
///
/// This is the whole of the reanimation-rights logic and is deliberately pure (no LDAP): it takes
/// a parsed [`SecurityDescriptor`] -- e.g. a tombstone's own `nTSecurityDescriptor`, as
/// [`TombstoneObject::from_entry`] passes it -- and returns one [`ReanimationPath`] per principal,
/// sorted by SID.
///
/// Reads *both* halves of the descriptor, which is the point: the DACL alone misses the
/// `OwnerSid`, and an owner can rewrite the DACL at will even with no ACE naming it. Deny/audit
/// ACEs (`is_allow_ace`) and inherit-only ACEs (`applies_to_self`) are excluded, since both can
/// carry the same access mask and object-type GUID as a real grant.
pub fn analyze_reanimation_control(sd: &SecurityDescriptor) -> Vec<ReanimationPath> {
    let mut by_sid: BTreeMap<String, BTreeSet<ReanimateMechanism>> = BTreeMap::new();

    if let Some(owner) = &sd.owner {
        by_sid
            .entry(owner.to_string())
            .or_default()
            .insert(ReanimateMechanism::Owner);
    }

    if let Some(dacl) = &sd.dacl {
        for ace in &dacl.aces {
            if !is_allow_ace(ace.ace_type) || !applies_to_self(ace.ace_flags) {
                continue;
            }

            let mut mechanisms = Vec::new();
            if grants_reanimate_right_on_object(ace) {
                mechanisms.push(ReanimateMechanism::ReanimateRight);
            }
            let (write_dac, write_owner) = grants_secdesc_write(ace);
            if write_dac {
                mechanisms.push(ReanimateMechanism::WriteDac);
            }
            if write_owner {
                mechanisms.push(ReanimateMechanism::WriteOwner);
            }
            if mechanisms.is_empty() {
                continue;
            }

            by_sid
                .entry(ace.sid.to_string())
                .or_default()
                .extend(mechanisms);
        }
    }

    by_sid
        .into_iter()
        .map(|(sid, mechanisms)| ReanimationPath {
            sid,
            mechanisms: mechanisms.into_iter().collect(),
        })
        .collect()
}

/// Pulls an attribute's raw bytes out of a search entry, checking `bin_attrs` first and falling
/// back to `attrs`.
///
/// `ldap3` routes a value into `attrs` instead of `bin_attrs` whenever it happens to be valid
/// UTF-8, which a binary `nTSecurityDescriptor` blob occasionally is; reading only `bin_attrs`
/// would silently drop the descriptor for those objects.
fn raw_attr(entry: &SearchEntry, name: &str) -> Option<Vec<u8>> {
    entry
        .bin_attrs
        .get(name)
        .and_then(|v| v.first())
        .cloned()
        .or_else(|| {
            entry
                .attrs
                .get(name)
                .and_then(|v| v.first())
                .map(|s| s.as_bytes().to_vec())
        })
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
    // it's included only for consistency with the other searches in this crate. SD_FLAGS, by
    // contrast, is required: without it the DC returns no descriptor at all to a bind without
    // SeSecurityPrivilege (see `sd_flags_control`).
    let ctrls = vec![
        RawControl {
            ctype: "1.2.840.113556.1.4.417".to_string(),
            crit: true,
            val: None,
        },
        sd_flags_control(),
    ];

    let opts = SearchOptions::new().timelimit(timeout_secs as i32);
    let (rs, _) = with_timeout(
        timeout_secs,
        ldap.with_controls(ctrls).with_search_options(opts).search(
            domain_nc,
            ldap3::Scope::Base,
            "(objectClass=*)",
            vec!["nTSecurityDescriptor"],
        ),
    )
    .await?
    .success()?;

    let mut principals = Vec::new();

    for entry in rs {
        let search_entry = SearchEntry::construct(entry);
        if let Some(sec_desc_bytes) = raw_attr(&search_entry, "nTSecurityDescriptor")
            && let Ok(sd) = SecurityDescriptor::parse(&sec_desc_bytes)
            && let Some(dacl) = &sd.dacl
        {
            for ace in &dacl.aces {
                // Only ACEs that actually grant the right: an actual grant (not a deny/audit ACE
                // reusing the same mask/GUID) that applies to this object itself (not
                // inherit-only). Ownership of the domain NC root is deliberately *not* counted
                // here -- this function answers "who holds the right domain-wide", and an
                // ACL-rewrite path on the NC root is a different (far broader) finding than
                // tombstone reanimation. Per-object ownership is handled by
                // `analyze_reanimation_control`.
                if is_allow_ace(ace.ace_type)
                    && applies_to_self(ace.ace_flags)
                    && grants_reanimate_right_at_nc_root(ace)
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
/// Uses the `SHOW_DELETED` control (to see the tombstones at all), `SHOW_DEACTIVATED_LINK` (to see
/// their preserved `memberOf` values, if any -- see [`TombstoneObject::member_of`]), and `SD_FLAGS`
/// (without which the DC returns no `nTSecurityDescriptor` at all to a bind lacking
/// `SeSecurityPrivilege`, taking every owner/DACL reanimation path with it). Pass the same
/// `recycle_bin_enabled` value obtained from [`check_recycle_bin_enabled`] earlier in the run.
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
        // Required for nTSecurityDescriptor to come back at all on a non-SeSecurityPrivilege
        // bind -- see `sd_flags_control`.
        sd_flags_control(),
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
                // Read per-tombstone so ownership and WRITE_DAC/WRITE_OWNER reanimation paths are
                // visible at all -- the domain-NC-root descriptor read by
                // `check_reanimate_rights` says nothing about who controls an individual
                // tombstone. Requires READ_CONTROL on the object *and* the SD_FLAGS control above;
                // silently absent otherwise.
                "nTSecurityDescriptor",
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

    const ACE_ALLOWED: u8 = 0x00;
    const ACE_ALLOWED_OBJECT: u8 = 0x05;
    const ACE_DENIED: u8 = 0x01;
    const ACE_INHERIT_ONLY: u8 = 0x08;
    const RIGHT_DS_READ_PROP: u32 = 0x0000_0010;

    /// `S-1-5-21-1-2-3-<rid>` in on-the-wire form.
    fn sid_bytes(rid: u32) -> Vec<u8> {
        // revision 1, 5 sub-authorities, identifier authority NT_AUTHORITY (5), big-endian.
        let mut out = vec![0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05];
        for sub in [21u32, 1, 2, 3, rid] {
            out.extend_from_slice(&sub.to_le_bytes());
        }
        out
    }

    fn sid_str(rid: u32) -> String {
        format!("S-1-5-21-1-2-3-{}", rid)
    }

    /// A non-object ACE (no object-type GUID), i.e. one whose access mask applies unscoped.
    fn plain_ace(ace_type: u8, ace_flags: u8, mask: u32, rid: u32) -> Vec<u8> {
        let sid = sid_bytes(rid);
        let mut out = vec![ace_type, ace_flags];
        out.extend_from_slice(&((8 + sid.len()) as u16).to_le_bytes());
        out.extend_from_slice(&mask.to_le_bytes());
        out.extend_from_slice(&sid);
        out
    }

    /// An object ACE carrying an `ACE_OBJECT_TYPE_PRESENT` GUID -- how a control access right like
    /// Reanimate-Tombstones is actually granted.
    fn object_ace(ace_type: u8, ace_flags: u8, mask: u32, object_type: Uuid, rid: u32) -> Vec<u8> {
        let sid = sid_bytes(rid);
        let mut out = vec![ace_type, ace_flags];
        out.extend_from_slice(&((12 + 16 + sid.len()) as u16).to_le_bytes());
        out.extend_from_slice(&mask.to_le_bytes());
        out.extend_from_slice(&0x0000_0001u32.to_le_bytes()); // ACE_OBJECT_TYPE_PRESENT
        out.extend_from_slice(&object_type.to_bytes_le());
        out.extend_from_slice(&sid);
        out
    }

    /// A self-relative security descriptor with the given owner (if any) and DACL.
    fn security_descriptor(owner_rid: Option<u32>, aces: &[Vec<u8>]) -> Vec<u8> {
        security_descriptor_with_control(owner_rid, aces, 0x8004)
    }

    /// As [`security_descriptor`], but with an explicit control word -- lets a test build a blob
    /// that happens to be valid UTF-8 (see `test_from_entry_reads_descriptor_from_attrs`).
    fn security_descriptor_with_control(
        owner_rid: Option<u32>,
        aces: &[Vec<u8>],
        control: u16,
    ) -> Vec<u8> {
        const HEADER_LEN: u32 = 20;
        let owner = owner_rid.map(sid_bytes).unwrap_or_default();
        let owner_offset = if owner.is_empty() { 0 } else { HEADER_LEN };
        let dacl_offset = HEADER_LEN + owner.len() as u32;
        let acl_size = (8 + aces.iter().map(Vec::len).sum::<usize>()) as u16;

        let mut out = vec![0x01, 0x00];
        out.extend_from_slice(&control.to_le_bytes());
        out.extend_from_slice(&owner_offset.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // group: absent
        out.extend_from_slice(&0u32.to_le_bytes()); // SACL: absent
        out.extend_from_slice(&dacl_offset.to_le_bytes());
        out.extend_from_slice(&owner);
        out.push(0x04); // ACL_REVISION_DS
        out.push(0x00);
        out.extend_from_slice(&acl_size.to_le_bytes());
        out.extend_from_slice(&(aces.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        for ace in aces {
            out.extend_from_slice(ace);
        }
        out
    }

    fn analyze(bytes: &[u8]) -> Vec<ReanimationPath> {
        let sd = SecurityDescriptor::parse(bytes).expect("test descriptor should parse");
        analyze_reanimation_control(&sd)
    }

    fn mechanisms_for(paths: &[ReanimationPath], rid: u32) -> Option<Vec<ReanimateMechanism>> {
        paths
            .iter()
            .find(|p| p.sid == sid_str(rid))
            .map(|p| p.mechanisms.clone())
    }

    /// Path A, unchanged: a control-access ACE scoped to the Reanimate-Tombstones GUID.
    #[test]
    fn test_analyze_reanimate_right_only() {
        let sd = security_descriptor(
            Some(500),
            &[object_ace(
                ACE_ALLOWED_OBJECT,
                0x00,
                RIGHT_DS_CONTROL_ACCESS,
                reanimate_tombstones_guid(),
                1104,
            )],
        );
        let paths = analyze(&sd);

        assert_eq!(
            mechanisms_for(&paths, 1104),
            Some(vec![ReanimateMechanism::ReanimateRight])
        );
        // The owner is a separate principal here, and is reported separately.
        assert_eq!(
            mechanisms_for(&paths, 500),
            Some(vec![ReanimateMechanism::Owner])
        );
    }

    /// A control-access ACE scoped to some *other* extended right doesn't grant reanimation.
    #[test]
    fn test_analyze_ignores_unrelated_extended_right() {
        let other_right = Uuid::parse_str("00299570-246d-11d0-a768-00aa006e0529").unwrap(); // User-Force-Change-Password
        let sd = security_descriptor(
            Some(500),
            &[object_ace(
                ACE_ALLOWED_OBJECT,
                0x00,
                RIGHT_DS_CONTROL_ACCESS,
                other_right,
                1104,
            )],
        );
        assert_eq!(mechanisms_for(&analyze(&sd), 1104), None);
    }

    /// Path B via ACE: `WRITE_DAC` alone, no extended right anywhere.
    #[test]
    fn test_analyze_write_dac_only() {
        let sd = security_descriptor(
            Some(500),
            &[plain_ace(ACE_ALLOWED, 0x00, RIGHT_WRITE_DAC, 1104)],
        );
        assert_eq!(
            mechanisms_for(&analyze(&sd), 1104),
            Some(vec![ReanimateMechanism::WriteDac])
        );
    }

    /// Path B via ACE: `WRITE_OWNER` alone.
    #[test]
    fn test_analyze_write_owner_only() {
        let sd = security_descriptor(
            Some(500),
            &[plain_ace(ACE_ALLOWED, 0x00, RIGHT_WRITE_OWNER, 1104)],
        );
        assert_eq!(
            mechanisms_for(&analyze(&sd), 1104),
            Some(vec![ReanimateMechanism::WriteOwner])
        );
    }

    /// Path B via ownership: the trustee holds no qualifying ACE at all -- only `OwnerSid` names
    /// it. This is the case a DACL-only walk misses entirely.
    #[test]
    fn test_analyze_owner_only_no_matching_ace() {
        let sd = security_descriptor(
            Some(1104),
            // A read-property ACE for the same principal: present in the DACL, but grants nothing
            // that qualifies.
            &[plain_ace(ACE_ALLOWED, 0x00, RIGHT_DS_READ_PROP, 1104)],
        );
        let paths = analyze(&sd);

        assert_eq!(paths.len(), 1);
        assert_eq!(
            mechanisms_for(&paths, 1104),
            Some(vec![ReanimateMechanism::Owner])
        );
    }

    /// An empty DACL still yields the owner.
    #[test]
    fn test_analyze_owner_with_empty_dacl() {
        let sd = security_descriptor(Some(1104), &[]);
        assert_eq!(
            mechanisms_for(&analyze(&sd), 1104),
            Some(vec![ReanimateMechanism::Owner])
        );
    }

    /// A principal qualifying several ways gets one entry, not one per mechanism/ACE, with the
    /// mechanisms recorded in precedence order.
    #[test]
    fn test_analyze_dedups_multiple_mechanisms_per_sid() {
        let sd = security_descriptor(
            Some(1104),
            &[
                object_ace(
                    ACE_ALLOWED_OBJECT,
                    0x00,
                    RIGHT_DS_CONTROL_ACCESS,
                    reanimate_tombstones_guid(),
                    1104,
                ),
                plain_ace(ACE_ALLOWED, 0x00, RIGHT_WRITE_DAC | RIGHT_WRITE_OWNER, 1104),
                // A second, redundant WRITE_DAC grant to the same principal.
                plain_ace(ACE_ALLOWED, 0x00, RIGHT_WRITE_DAC, 1104),
            ],
        );
        let paths = analyze(&sd);

        assert_eq!(paths.len(), 1, "expected one path per SID, got {:?}", paths);
        assert_eq!(
            paths[0].mechanisms,
            vec![
                ReanimateMechanism::ReanimateRight,
                ReanimateMechanism::Owner,
                ReanimateMechanism::WriteDac,
                ReanimateMechanism::WriteOwner,
            ]
        );
        assert_eq!(paths[0].primary(), ReanimateMechanism::ReanimateRight);
    }

    /// `GenericAll` on a *tombstone* buys the ability to rewrite that object's descriptor, not the
    /// Reanimate-Tombstones right itself (which is validated at the domain NC root) -- so it is
    /// reported as write_dac/write_owner, the mechanisms that actually require an ACL rewrite first.
    #[test]
    fn test_analyze_generic_all_on_object_is_secdesc_write_not_extended_right() {
        let sd = security_descriptor(
            Some(500),
            &[plain_ace(ACE_ALLOWED, 0x00, RIGHT_GENERIC_ALL, 1104)],
        );
        assert_eq!(
            mechanisms_for(&analyze(&sd), 1104),
            Some(vec![
                ReanimateMechanism::WriteDac,
                ReanimateMechanism::WriteOwner
            ])
        );
    }

    /// Same rule for an *unscoped* control-access ACE (no object_type): at object level it names no
    /// extended right, so it must not be reported as reanimate_right. It also grants no
    /// descriptor-write bit, so it qualifies for nothing at all.
    #[test]
    fn test_analyze_unscoped_control_access_on_object_is_not_reanimate_right() {
        let sd = security_descriptor(
            Some(500),
            &[plain_ace(ACE_ALLOWED, 0x00, RIGHT_DS_CONTROL_ACCESS, 1104)],
        );
        assert_eq!(mechanisms_for(&analyze(&sd), 1104), None);
    }

    /// The domain-NC-root rule is deliberately looser -- an unscoped control-access grant there does
    /// cover every extended right, Reanimate-Tombstones included. This is what
    /// `check_reanimate_rights` uses, and it must not be tightened along with the object-level rule.
    #[test]
    fn test_nc_root_rule_accepts_unscoped_control_access() {
        let unscoped = Ace {
            ace_type: ACE_ALLOWED,
            ace_flags: 0x00,
            access_mask: RIGHT_DS_CONTROL_ACCESS,
            object_type: None,
            inherited_object_type: None,
            sid: ad_secdesc::Sid::parse(&mut std::io::Cursor::new(sid_bytes(1104).as_slice()))
                .unwrap(),
        };
        assert!(grants_reanimate_right_at_nc_root(&unscoped));
        // ...and the object-level rule rejects the very same ACE.
        assert!(!grants_reanimate_right_on_object(&unscoped));
    }

    /// Deny and inherit-only ACEs carry the same masks as real grants and must not count.
    #[test]
    fn test_analyze_skips_deny_and_inherit_only_aces() {
        let sd = security_descriptor(
            Some(500),
            &[
                plain_ace(ACE_DENIED, 0x00, RIGHT_WRITE_DAC, 1104),
                plain_ace(ACE_ALLOWED, ACE_INHERIT_ONLY, RIGHT_WRITE_OWNER, 1105),
            ],
        );
        let paths = analyze(&sd);

        assert_eq!(mechanisms_for(&paths, 1104), None);
        assert_eq!(mechanisms_for(&paths, 1105), None);
        assert_eq!(paths.len(), 1); // the owner only
    }

    #[test]
    fn test_mechanism_edge_property_strings() {
        assert_eq!(
            ReanimateMechanism::ReanimateRight.as_str(),
            "reanimate_right"
        );
        assert_eq!(ReanimateMechanism::Owner.as_str(), "owner");
        assert_eq!(ReanimateMechanism::WriteDac.as_str(), "write_dac");
        assert_eq!(ReanimateMechanism::WriteOwner.as_str(), "write_owner");
    }

    #[test]
    fn test_tombstone_from_entry_parses_owner_and_paths() {
        let mut attrs = HashMap::new();
        attrs.insert("isDeleted".to_string(), vec!["TRUE".to_string()]);

        let mut bin_attrs = HashMap::new();
        bin_attrs.insert("objectGUID".to_string(), vec![vec![0; 16]]);
        bin_attrs.insert(
            "nTSecurityDescriptor".to_string(),
            vec![security_descriptor(
                Some(1104),
                &[plain_ace(ACE_ALLOWED, 0x00, RIGHT_WRITE_DAC, 1105)],
            )],
        );

        let entry = SearchEntry {
            dn: "CN=cert_admin,CN=Deleted Objects,DC=ghost,DC=local".to_string(),
            attrs,
            bin_attrs,
        };

        let tombstone = TombstoneObject::from_entry(&entry, true).unwrap();
        assert_eq!(tombstone.owner_sid, Some(sid_str(1104)));
        assert_eq!(
            mechanisms_for(&tombstone.reanimation_paths, 1104),
            Some(vec![ReanimateMechanism::Owner])
        );
        assert_eq!(
            mechanisms_for(&tombstone.reanimation_paths, 1105),
            Some(vec![ReanimateMechanism::WriteDac])
        );
    }

    /// No `READ_CONTROL` on the tombstone means AD omits the attribute; that degrades to "no
    /// ownership data" instead of failing the object.
    #[test]
    fn test_tombstone_from_entry_without_descriptor() {
        let mut attrs = HashMap::new();
        attrs.insert("isDeleted".to_string(), vec!["TRUE".to_string()]);

        let mut bin_attrs = HashMap::new();
        bin_attrs.insert("objectGUID".to_string(), vec![vec![0; 16]]);

        let entry = SearchEntry {
            dn: "CN=opaque,CN=Deleted Objects,DC=ghost,DC=local".to_string(),
            attrs,
            bin_attrs,
        };

        let tombstone = TombstoneObject::from_entry(&entry, true).unwrap();
        assert_eq!(tombstone.owner_sid, None);
        assert!(tombstone.reanimation_paths.is_empty());
    }

    /// A malformed descriptor is also non-fatal.
    #[test]
    fn test_tombstone_from_entry_with_malformed_descriptor() {
        let mut attrs = HashMap::new();
        attrs.insert("isDeleted".to_string(), vec!["TRUE".to_string()]);

        let mut bin_attrs = HashMap::new();
        bin_attrs.insert("objectGUID".to_string(), vec![vec![0; 16]]);
        bin_attrs.insert(
            "nTSecurityDescriptor".to_string(),
            vec![vec![0x01, 0x00, 0x04, 0x80]], // truncated header
        );

        let entry = SearchEntry {
            dn: "CN=broken,CN=Deleted Objects,DC=ghost,DC=local".to_string(),
            attrs,
            bin_attrs,
        };

        let tombstone = TombstoneObject::from_entry(&entry, true).unwrap();
        assert_eq!(tombstone.owner_sid, None);
        assert!(tombstone.reanimation_paths.is_empty());
    }

    /// `ldap3` puts a value in `attrs` rather than `bin_attrs` whenever it happens to be valid
    /// UTF-8, which some descriptor blobs are; `raw_attr` must find it either way.
    #[test]
    fn test_from_entry_reads_descriptor_from_attrs() {
        // control 0x0004 (SE_DACL_PRESENT, no SE_SELF_RELATIVE bit) and a WRITE_DAC mask keep
        // every byte of this blob inside valid UTF-8.
        let sd_bytes = security_descriptor_with_control(
            Some(1104),
            &[plain_ace(ACE_ALLOWED, 0x00, RIGHT_WRITE_DAC, 1105)],
            0x0004,
        );
        let sd_string =
            String::from_utf8(sd_bytes).expect("test blob is intentionally valid UTF-8");

        let mut attrs = HashMap::new();
        attrs.insert("isDeleted".to_string(), vec!["TRUE".to_string()]);
        attrs.insert("nTSecurityDescriptor".to_string(), vec![sd_string]);

        let mut bin_attrs = HashMap::new();
        bin_attrs.insert("objectGUID".to_string(), vec![vec![0; 16]]);

        let entry = SearchEntry {
            dn: "CN=utf8sd,CN=Deleted Objects,DC=ghost,DC=local".to_string(),
            attrs,
            bin_attrs,
        };

        let tombstone = TombstoneObject::from_entry(&entry, true).unwrap();
        assert_eq!(tombstone.owner_sid, Some(sid_str(1104)));
        assert_eq!(
            mechanisms_for(&tombstone.reanimation_paths, 1105),
            Some(vec![ReanimateMechanism::WriteDac])
        );
    }

    /// The SD_FLAGS control value is hand-encoded BER; a wrong byte here silently costs every
    /// owner/DACL finding, since the DC then omits `nTSecurityDescriptor` rather than erroring.
    #[test]
    fn test_sd_flags_control_encoding() {
        let ctrl = sd_flags_control();
        assert_eq!(ctrl.ctype, "1.2.840.113556.1.4.801");
        assert!(!ctrl.crit, "must degrade, not fail, on an unsupporting DC");
        // SEQUENCE (0x30), length 3, INTEGER (0x02), length 1, OWNER|GROUP|DACL (0x07).
        assert_eq!(ctrl.val, Some(vec![0x30, 0x03, 0x02, 0x01, 0x07]));
        // SACL (0x08) must stay unset: reading it needs SeSecurityPrivilege.
        assert_eq!(SD_FLAGS_OWNER_GROUP_DACL[4] & 0x08, 0);
    }

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
