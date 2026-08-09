//! GhostHound CLI: enumerates Active Directory tombstones and reanimation rights over LDAP and
//! emits a [BloodHound](https://github.com/SpecterOps/BloodHound) OpenGraph JSON payload. See the
//! [repository README](https://github.com/JVBotelho/ghosthound) for usage, prerequisites, and
//! BloodHound import steps; run `ghosthound --help` for the full flag list.

#![forbid(unsafe_code)]

use ad_tombstone::{
    ReanimateMechanism, ReanimationPath, check_reanimate_rights, check_recycle_bin_enabled,
    fetch_tombstones, resolve_object_sid, with_timeout,
};
use bloodhound_opengraph::{Edge, Node, OpenGraphBuilder};
use clap::Parser;
use ldap3::{LdapConnAsync, LdapConnSettings};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::Write;
use std::time::Duration;
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

#[derive(Parser)]
#[command(
    version,
    about = "GhostHound CLI - Discover AD Tombstones and Reanimation Paths"
)]
struct Args {
    /// Domain name (e.g. ghost.local)
    #[arg(short, long)]
    domain: String,

    /// IP Address of the Domain Controller
    #[arg(long)]
    dc_ip: String,

    /// Username for authentication
    #[arg(short, long)]
    username: String,

    /// Password for authentication. Prefer the LDAP_PASSWORD env var or the interactive
    /// prompt (leave unset) over this flag: a value passed here is visible to other local
    /// users via `ps`/`/proc/<pid>/cmdline` and lands in shell history.
    #[arg(short, long, env = "LDAP_PASSWORD", hide_env_values = true)]
    password: Option<String>,

    /// Disable LDAPS (port 636) and use cleartext LDAP (port 389)
    #[arg(long, default_value_t = false)]
    disable_ldaps: bool,

    /// Skip LDAPS certificate verification (self-signed/lab certs). The connection stays
    /// encrypted; only certificate trust is skipped. For lab use, not production engagements.
    #[arg(long, default_value_t = false)]
    insecure_tls: bool,

    /// Use NTLM authentication (currently disabled due to upstream supply-chain issues)
    #[arg(long, default_value_t = false)]
    ntlm: bool,

    /// Seconds to wait for the DC to respond (connection and each search) before giving up.
    /// Applies to both the initial connect and every subsequent LDAP operation, so a wrong
    /// --dc-ip or a firewalled/unreachable DC fails within this bound instead of hanging.
    #[arg(long, default_value_t = 30)]
    timeout_secs: u64,

    /// Output JSON file name
    #[arg(short, long, default_value = "ghosthound_output.json")]
    output: String,
}

/// Rewrites a well-known SID into the domain-scoped form BloodHound itself uses as `objectid`.
///
/// SharpHound/RustHound-CE store non-domain principals (BUILTIN groups, `NT AUTHORITY\SYSTEM`,
/// Authenticated Users, ...) as `<DOMAIN FQDN UPPERCASE>-<SID>` -- e.g.
/// `TOMBWATCHER.HTB-S-1-5-32-544` -- because the same well-known SID means a different principal in
/// every domain. Emitting the bare `S-1-5-32-544` produces a placeholder whose `objectid` matches no
/// real node, so `bridge_shadow_nodes.cypher` can never pair it and those edges stay stranded
/// (observed in the lab: the SYSTEM/Administrators/Account Operators shadows were the only
/// unbridged ones).
///
/// A real domain SID (`S-1-5-21-<domain>-<rid>`) is already globally unique and is passed through
/// untouched. Anything else gets the domain prefix; for an exotic non-AD SID that BloodHound has no
/// node for either way (`S-1-5-80-*` service SIDs, say), the result is still an unbridged
/// placeholder -- no worse than the bare form, and never a false pairing.
fn graph_principal_id(sid: &str, domain: &str) -> String {
    if sid.starts_with("S-1-5-21-") {
        sid.to_string()
    } else {
        format!("{}-{}", domain.to_uppercase(), sid)
    }
}

/// Builds the `GhostHound_CanReanimate` edges pointing at one tombstone.
///
/// Both reanimation paths land here: `domain_rights` is the set of SIDs holding the
/// Reanimate-Tombstones right domain-wide (read off the domain NC root, so it applies to every
/// tombstone), and `object_paths` is control over this specific object's security descriptor --
/// ownership, `WRITE_DAC`, `WRITE_OWNER`, or an inherited Reanimate-Tombstones ACE.
///
/// The same principal can qualify both ways, so mechanisms are merged per SID into a single edge
/// carrying all of them rather than one edge per mechanism -- the same one-edge-per-principal rule
/// `check_reanimate_rights` already applies to its own SID list.
fn reanimation_edges(
    target_id: &str,
    domain: &str,
    domain_rights: &[String],
    object_paths: &[ReanimationPath],
) -> Vec<Edge> {
    let mut mechanisms_by_sid: BTreeMap<&str, BTreeSet<ReanimateMechanism>> = BTreeMap::new();
    for sid in domain_rights {
        mechanisms_by_sid
            .entry(sid.as_str())
            .or_default()
            .insert(ReanimateMechanism::ReanimateRight);
    }
    for path in object_paths {
        mechanisms_by_sid
            .entry(path.sid.as_str())
            .or_default()
            .extend(path.mechanisms.iter().copied());
    }

    mechanisms_by_sid
        .into_iter()
        .filter_map(|(sid, mechanisms)| {
            // Non-empty by construction (every entry is created with at least one mechanism).
            let primary = *mechanisms.iter().next()?;
            // Well-known SIDs (BUILTIN groups, SYSTEM, ...) must be domain-scoped to match the
            // objectid BloodHound already stores for them -- see `graph_principal_id`.
            let start =
                bloodhound_opengraph::EdgeEndpoint::new(graph_principal_id(sid, domain), "id");
            let end = bloodhound_opengraph::EdgeEndpoint::new(target_id.to_string(), "id");
            // Kind must match model.json's relationship_kinds[].name exactly, same reasoning as
            // the node kinds.
            let mut edge = Edge::new(start, end, "GhostHound_CanReanimate");
            // `source` is the single strongest mechanism (reanimate_right > owner > write_dac >
            // write_owner) so a Cypher query can filter on one scalar value; `sources` lists every
            // mechanism for the cases where that matters. The distinction is operational:
            // reanimate_right is already granted, while the others require first rewriting the
            // tombstone's DACL -- a loud, auditable extra step.
            edge.add_property("source", json!(primary.as_str()));
            edge.add_property(
                "sources",
                json!(mechanisms.iter().map(|m| m.as_str()).collect::<Vec<_>>()),
            );
            Some(edge)
        })
        .collect()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.ntlm {
        return Err("NTLM authentication is currently disabled due to upstream dependencies (sspi-rs) failing strict security checks on the latest compiler toolchain. Please use Simple Bind.".into());
    }

    let password = Zeroizing::new(match args.password {
        Some(p) => p,
        None => rpassword::prompt_password("Password: ")?,
    });

    let port = if !args.disable_ldaps { 636 } else { 389 };
    let protocol = if !args.disable_ldaps { "ldaps" } else { "ldap" };
    let ldap_url = format!("{}://{}:{}", protocol, args.dc_ip, port);

    println!("[*] Connecting to {}...", ldap_url);
    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(args.timeout_secs))
        .set_no_tls_verify(args.insecure_tls);
    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &ldap_url)
        .await
        .map_err(|e| {
            format!(
                "failed to connect to {} within {}s ({}). Check --dc-ip, network reachability, \
                 and firewall rules; if using LDAPS with a self-signed/lab certificate, also try \
                 --insecure-tls.",
                ldap_url, args.timeout_secs, e
            )
        })?;
    ldap3::drive!(conn);

    let bind_dn = format!("{}@{}", args.username, args.domain);
    println!("[*] Authenticating as {}...", bind_dn);
    with_timeout(args.timeout_secs, ldap.simple_bind(&bind_dn, &password))
        .await?
        .success()?;
    println!("[+] Authentication successful.");

    println!("[*] Fetching defaultNamingContext...");
    let (rs_root, _) = with_timeout(
        args.timeout_secs,
        ldap.search(
            "",
            ldap3::Scope::Base,
            "(objectClass=*)",
            vec!["defaultNamingContext"],
        ),
    )
    .await?
    .success()?;

    let domain_nc = if let Some(entry) = rs_root.first() {
        let search_entry = ldap3::SearchEntry::construct(entry.clone());
        search_entry
            .attrs
            .get("defaultNamingContext")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default()
    } else {
        return Err("Could not get defaultNamingContext".into());
    };

    if domain_nc.is_empty() {
        return Err("Empty defaultNamingContext".into());
    }
    println!("[+] Domain NC: {}", domain_nc);

    println!("[*] Checking if Recycle Bin is enabled...");
    let recycle_bin_enabled = check_recycle_bin_enabled(&mut ldap, args.timeout_secs).await?;
    println!("[+] Recycle Bin enabled: {}", recycle_bin_enabled);

    println!("[*] Fetching tombstones from Deleted Objects...");
    let tombstones = fetch_tombstones(
        &mut ldap,
        &domain_nc,
        recycle_bin_enabled,
        args.timeout_secs,
    )
    .await?;
    println!("[+] Found {} tombstones.", tombstones.len());

    println!("[*] Checking for reanimation rights on the domain naming context root...");
    let reanimate_rights = check_reanimate_rights(&mut ldap, &domain_nc, args.timeout_secs).await?;
    println!(
        "[+] Found {} SIDs with the Reanimate-Tombstones right domain-wide.",
        reanimate_rights.len()
    );

    // Ownership/WRITE_DAC/WRITE_OWNER on an individual tombstone is a reanimation path too (the
    // principal rewrites that object's DACL to grant itself the right), and it lives in the
    // tombstone's own nTSecurityDescriptor rather than the domain NC root's. A tombstone whose
    // descriptor wasn't readable (no READ_CONTROL for the bound principal) is reported rather than
    // silently treated as "nobody controls this".
    let per_object_controllers: usize = tombstones.iter().map(|t| t.reanimation_paths.len()).sum();
    println!(
        "[+] Found {} owner/WRITE_DAC/WRITE_OWNER reanimation paths on individual tombstones.",
        per_object_controllers
    );
    let opaque_tombstones = tombstones.iter().filter(|t| t.owner_sid.is_none()).count();
    if opaque_tombstones > 0 {
        eprintln!(
            "[!] {} of {} tombstones had no readable nTSecurityDescriptor (READ_CONTROL denied or \
             malformed); their ownership/DACL reanimation paths are not represented in the output.",
            opaque_tombstones,
            tombstones.len()
        );
    }

    println!("[*] Resolving preserved group memberships to SIDs...");
    let mut group_dn_to_sid: HashMap<String, String> = HashMap::new();
    for t in &tombstones {
        for dn in &t.member_of {
            if group_dn_to_sid.contains_key(dn) {
                continue;
            }
            if let Some(sid) = resolve_object_sid(&mut ldap, dn, args.timeout_secs).await? {
                group_dn_to_sid.insert(dn.clone(), sid);
            }
        }
    }

    println!("[*] Building OpenGraph JSON...");
    let mut builder = OpenGraphBuilder::new();

    for t in &tombstones {
        // These must match crates/ad-tombstone/model.json's node_kinds[].name exactly (the
        // "GhostHound_" namespace prefix per BloodHound's extension-definition convention) --
        // a payload node's `kinds` entry that doesn't match a registered node_kinds.name is
        // dropped from the structured graph on import.
        let label = if t
            .object_class
            .iter()
            .any(|c| c.eq_ignore_ascii_case("user") || c.eq_ignore_ascii_case("person"))
        {
            "GhostHound_TombstoneUser"
        } else if t
            .object_class
            .iter()
            .any(|c| c.eq_ignore_ascii_case("computer"))
        {
            "GhostHound_TombstoneComputer"
        } else if t
            .object_class
            .iter()
            .any(|c| c.eq_ignore_ascii_case("group"))
        {
            "GhostHound_TombstoneGroup"
        } else {
            "GhostHound_TombstoneUser"
        };

        let target_id = t
            .object_sid
            .clone()
            .unwrap_or_else(|| t.object_guid.clone());
        if target_id.is_empty() {
            // Neither objectSid nor a parseable objectGUID (from_entry yields "" if the raw
            // bytes weren't exactly 16 bytes) -- nothing usable to key this node or its edges on.
            eprintln!(
                "[!] Skipping tombstone at {} -- no usable objectSid/objectGUID",
                t.dn
            );
            continue;
        }
        let mut node = Node::new(target_id.clone(), label);
        if let Some(sam) = &t.sam_account_name {
            // Matches BloodHound's own display convention for AD principals
            // (SAMACCOUNTNAME@DOMAIN.TLD, uppercased) -- without this, a tombstone renders as a
            // bare SID/GUID string instead of a readable name.
            node.add_property(
                "name",
                json!(format!("{}@{}", sam, args.domain).to_uppercase()),
            );
        }
        node.add_property("is_recycled", json!(t.is_recycled));
        node.add_property("recycle_bin_enabled", json!(t.recycle_bin_enabled));
        node.add_property(
            "group_membership_recoverable",
            json!(t.group_membership_recoverable),
        );
        if let Some(parent) = &t.lastknownparent {
            node.add_property("lastknownparent", json!(parent));
        }
        // The object's own owner, from its nTSecurityDescriptor. Surfaced on the node (not only
        // as an edge) because "who owns this tombstone" is a fact about the object that an analyst
        // reads directly, and it's what makes the corresponding owner-sourced edge explainable.
        if let Some(owner) = &t.owner_sid {
            node.add_property("ownersid", json!(graph_principal_id(owner, &args.domain)));
        }

        builder.add_node(node);

        for edge in reanimation_edges(
            &target_id,
            &args.domain,
            &reanimate_rights,
            &t.reanimation_paths,
        ) {
            builder.add_edge(edge);
        }

        // Edges: groups this tombstone was a member of, still walkable while in the
        // recoverable "Deleted" state -- without this, reanimating back into e.g. Domain
        // Admins is a dead end in the graph even though AD itself preserves the membership.
        // This targets the group by bare "id" reference, which does NOT merge into the real
        // Group node RustHound-CE/SharpHound already created (BloodHound's OpenGraph ingest
        // scopes relationship-endpoint identity to GhostHound's own source kind regardless of
        // match strategy -- see resolve_object_sid's doc comment and docs/adr/0006). It creates
        // a separate placeholder node sharing the same `objectid` property instead;
        // `bridge_shadow_nodes.cypher` links it to the real node afterward.
        for dn in &t.member_of {
            if let Some(group_sid) = group_dn_to_sid.get(dn) {
                let start = bloodhound_opengraph::EdgeEndpoint::new(target_id.clone(), "id");
                let end = bloodhound_opengraph::EdgeEndpoint::new(
                    graph_principal_id(group_sid, &args.domain),
                    "id",
                );
                builder.add_edge(Edge::new(start, end, "GhostHound_WasMemberOf"));
            }
        }
    }

    let graph_data = builder.build("GhostHound");
    let json_output = serde_json::to_string_pretty(&graph_data)?;
    // The output documents privileged principals and attack paths, so restrict it to the owner
    // rather than relying on the process umask (typically 644, world-readable) on Unix.
    let mut open_options = File::options();
    open_options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    open_options.mode(0o600);
    let mut file = open_options.open(&args.output)?;
    file.write_all(json_output.as_bytes())?;

    println!("[+] Successfully wrote graph data to {}", args.output);

    ldap.unbind().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(sid: &str, mechanisms: &[ReanimateMechanism]) -> ReanimationPath {
        ReanimationPath {
            sid: sid.to_string(),
            mechanisms: mechanisms.to_vec(),
        }
    }

    fn source_of(edge: &Edge) -> &str {
        edge.properties["source"].as_str().unwrap()
    }

    fn sources_of(edge: &Edge) -> Vec<&str> {
        edge.properties["sources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect()
    }

    /// Path A alone: the domain-wide right, applied to every tombstone.
    #[test]
    fn test_edges_from_domain_right_only() {
        let edges = reanimation_edges(
            "S-1-5-21-1-2-3-1109",
            "ghost.local",
            &["S-1-5-32-544".to_string()],
            &[],
        );

        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].kind, "GhostHound_CanReanimate");
        // Well-known SID, domain-scoped to match BloodHound's own objectid for it.
        assert_eq!(edges[0].start.value, "GHOST.LOCAL-S-1-5-32-544");
        assert_eq!(edges[0].end.value, "S-1-5-21-1-2-3-1109");
        assert_eq!(source_of(&edges[0]), "reanimate_right");
        assert_eq!(sources_of(&edges[0]), vec!["reanimate_right"]);
    }

    /// Path B alone -- the case that previously produced no edge at all: a principal with only
    /// ownership plus WRITE_DAC/WRITE_OWNER on the tombstone, and no formal extended right
    /// anywhere.
    #[test]
    fn test_edges_from_object_control_only() {
        let edges = reanimation_edges(
            "S-1-5-21-1-2-3-1109",
            "ghost.local",
            &[],
            &[path(
                "S-1-5-21-1-2-3-1104",
                &[
                    ReanimateMechanism::Owner,
                    ReanimateMechanism::WriteDac,
                    ReanimateMechanism::WriteOwner,
                ],
            )],
        );

        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].start.value, "S-1-5-21-1-2-3-1104");
        assert_eq!(source_of(&edges[0]), "owner");
        assert_eq!(
            sources_of(&edges[0]),
            vec!["owner", "write_dac", "write_owner"]
        );
    }

    #[test]
    fn test_edge_source_for_write_dac_only() {
        let edges = reanimation_edges(
            "S-1-5-21-1-2-3-1109",
            "ghost.local",
            &[],
            &[path("S-1-5-21-1-2-3-1104", &[ReanimateMechanism::WriteDac])],
        );

        assert_eq!(source_of(&edges[0]), "write_dac");
        assert_eq!(sources_of(&edges[0]), vec!["write_dac"]);
    }

    /// A principal qualifying via both paths gets one edge recording both, not two edges.
    #[test]
    fn test_edges_dedup_across_both_paths() {
        let edges = reanimation_edges(
            "S-1-5-21-1-2-3-1109",
            "ghost.local",
            &["S-1-5-21-1-2-3-1104".to_string()],
            &[path("S-1-5-21-1-2-3-1104", &[ReanimateMechanism::Owner])],
        );

        assert_eq!(
            edges.len(),
            1,
            "expected one edge per principal: {:?}",
            edges
        );
        // The formal grant wins as the scalar `source`: it needs no ACL rewrite first.
        assert_eq!(source_of(&edges[0]), "reanimate_right");
        assert_eq!(sources_of(&edges[0]), vec!["reanimate_right", "owner"]);
    }

    /// Distinct principals still get one edge each, in a deterministic order.
    #[test]
    fn test_edges_for_distinct_principals() {
        let edges = reanimation_edges(
            "S-1-5-21-1-2-3-1109",
            "ghost.local",
            &["S-1-5-32-544".to_string()],
            &[path("S-1-5-21-1-2-3-1104", &[ReanimateMechanism::Owner])],
        );

        assert_eq!(edges.len(), 2);
        assert_eq!(edges[0].start.value, "S-1-5-21-1-2-3-1104");
        assert_eq!(edges[1].start.value, "GHOST.LOCAL-S-1-5-32-544");
    }

    /// A domain principal's SID is globally unique and must pass through untouched -- prefixing it
    /// would break the match against the real node.
    #[test]
    fn test_graph_principal_id_passes_through_domain_sids() {
        assert_eq!(
            graph_principal_id(
                "S-1-5-21-1392491010-1358638721-2126982587-1106",
                "tombwatcher.htb"
            ),
            "S-1-5-21-1392491010-1358638721-2126982587-1106"
        );
    }

    /// Well-known SIDs mean a different principal per domain, so BloodHound stores them scoped --
    /// e.g. TOMBWATCHER.HTB-S-1-5-32-544. Emitting the bare SID leaves the shadow node unbridgeable.
    #[test]
    fn test_graph_principal_id_scopes_well_known_sids() {
        for sid in [
            "S-1-5-32-544",
            "S-1-5-32-548",
            "S-1-5-18",
            "S-1-5-11",
            "S-1-1-0",
        ] {
            assert_eq!(
                graph_principal_id(sid, "tombwatcher.htb"),
                format!("TOMBWATCHER.HTB-{}", sid)
            );
        }
    }

    #[test]
    fn test_no_edges_when_nothing_qualifies() {
        assert!(reanimation_edges("S-1-5-21-1-2-3-1109", "ghost.local", &[], &[]).is_empty());
    }
}
