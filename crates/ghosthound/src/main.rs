use ad_tombstone::{
    check_reanimate_rights, check_recycle_bin_enabled, fetch_tombstones, resolve_object_sid,
    with_timeout,
};
use bloodhound_opengraph::{Edge, Node, OpenGraphBuilder};
use clap::Parser;
use ldap3::{LdapConnAsync, LdapConnSettings};
use serde_json::json;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::time::Duration;

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.ntlm {
        return Err("NTLM authentication is currently disabled due to upstream dependencies (sspi-rs) failing strict security checks on the latest compiler toolchain. Please use Simple Bind.".into());
    }

    let password = match args.password {
        Some(p) => p,
        None => rpassword::prompt_password("Password: ")?,
    };

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
        "[+] Found {} SIDs with reanimation rights.",
        reanimate_rights.len()
    );

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

    // Domain Node
    let mut domain_node = Node::new(domain_nc.clone(), "Domain");
    domain_node.add_property("name", json!(args.domain.to_uppercase()));
    builder.add_node(domain_node);

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
        let mut node = Node::new(target_id.clone(), label);
        node.add_property("is_recycled", json!(t.is_recycled));
        node.add_property("recycle_bin_enabled", json!(t.recycle_bin_enabled));
        node.add_property(
            "group_membership_recoverable",
            json!(t.group_membership_recoverable),
        );
        if let Some(parent) = &t.lastknownparent {
            node.add_property("lastknownparent", json!(parent));
        }

        builder.add_node(node);

        // Edges: Principals with the reanimation right can reanimate this tombstone. Kind
        // must match model.json's relationship_kinds[].name exactly, same reasoning as above.
        for sid in &reanimate_rights {
            let start = bloodhound_opengraph::EdgeEndpoint::new(sid.clone(), "id");
            let end = bloodhound_opengraph::EdgeEndpoint::new(target_id.clone(), "id");
            builder.add_edge(Edge::new(start, end, "GhostHound_CanReanimate"));
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
                let end = bloodhound_opengraph::EdgeEndpoint::new(group_sid.clone(), "id");
                builder.add_edge(Edge::new(start, end, "GhostHound_WasMemberOf"));
            }
        }
    }

    let graph_data = builder.build("GhostHound");
    let json_output = serde_json::to_string_pretty(&graph_data)?;
    let mut file = File::create(&args.output)?;
    file.write_all(json_output.as_bytes())?;

    println!("[+] Successfully wrote graph data to {}", args.output);

    ldap.unbind().await?;
    Ok(())
}
