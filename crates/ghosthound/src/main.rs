use ad_tombstone::{check_reanimate_rights, check_recycle_bin_enabled, fetch_tombstones};
use bloodhound_opengraph::{Edge, Node, OpenGraphBuilder};
use clap::Parser;
use ldap3::{LdapConnAsync, LdapConnSettings};
use serde_json::json;
use std::fs::File;
use std::io::Write;

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

    /// Use NTLM authentication (currently disabled due to upstream supply-chain issues)
    #[arg(long, default_value_t = false)]
    ntlm: bool,

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
    let settings = LdapConnSettings::new();
    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &ldap_url).await?;
    ldap3::drive!(conn);

    let bind_dn = format!("{}@{}", args.username, args.domain);
    println!("[*] Authenticating as {}...", bind_dn);
    ldap.simple_bind(&bind_dn, &password).await?.success()?;
    println!("[+] Authentication successful.");

    println!("[*] Fetching defaultNamingContext...");
    let (rs_root, _) = ldap
        .search(
            "",
            ldap3::Scope::Base,
            "(objectClass=*)",
            vec!["defaultNamingContext"],
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
    let recycle_bin_enabled = check_recycle_bin_enabled(&mut ldap).await?;
    println!("[+] Recycle Bin enabled: {}", recycle_bin_enabled);

    println!("[*] Fetching tombstones from Deleted Objects...");
    let tombstones = fetch_tombstones(&mut ldap, &domain_nc, recycle_bin_enabled).await?;
    println!("[+] Found {} tombstones.", tombstones.len());

    println!("[*] Checking for reanimation rights on Deleted Objects container...");
    let reanimate_rights = check_reanimate_rights(&mut ldap, &domain_nc).await?;
    println!(
        "[+] Found {} SIDs with reanimation rights.",
        reanimate_rights.len()
    );

    println!("[*] Building OpenGraph JSON...");
    let mut builder = OpenGraphBuilder::new();

    // Domain Node
    let mut domain_node = Node::new(domain_nc.clone(), "Domain");
    domain_node.add_property("name", json!(args.domain.to_uppercase()));
    builder.add_node(domain_node);

    for t in &tombstones {
        let label = if t
            .object_class
            .iter()
            .any(|c| c.eq_ignore_ascii_case("user") || c.eq_ignore_ascii_case("person"))
        {
            "TombstoneUser"
        } else if t
            .object_class
            .iter()
            .any(|c| c.eq_ignore_ascii_case("computer"))
        {
            "TombstoneComputer"
        } else if t
            .object_class
            .iter()
            .any(|c| c.eq_ignore_ascii_case("group"))
        {
            "TombstoneGroup"
        } else {
            "TombstoneUser"
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

        // Edges: Principals with CanReanimate right can reanimate this tombstone
        for sid in &reanimate_rights {
            let start = bloodhound_opengraph::EdgeEndpoint::new(sid.clone(), "id");
            let end = bloodhound_opengraph::EdgeEndpoint::new(target_id.clone(), "id");
            builder.add_edge(Edge::new(start, end, "CanReanimate"));
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
