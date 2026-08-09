# GhostHound

[![Crates.io](https://img.shields.io/crates/v/ghosthound.svg)](https://crates.io/crates/ghosthound)
[![docs.rs](https://img.shields.io/docsrs/ghosthound)](https://docs.rs/ghosthound)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/JVBotelho/ghosthound/badge)](https://securityscorecards.dev/viewer/?uri=github.com/JVBotelho/ghosthound)

GhostHound is a [BloodHound](https://github.com/SpecterOps/BloodHound) OpenGraph extension for
Active Directory. SharpHound and every other AD collector skip `CN=Deleted Objects`: deleted
objects (tombstones) are invisible to standard BloodHound attack-path analysis, even though the AD
Recycle Bin and tombstone reanimation mechanisms can let a sufficiently-privileged principal
restore one — and take over whatever identity it represents. GhostHound enumerates tombstones over
LDAP with the `SHOW_DELETED` control, determines who can reanimate each one, and emits an OpenGraph
JSON payload plus a `model.json` extension definition so BloodHound CE v8+ can render this as a
first-class part of the graph.

**Authorized use only.** This is an offensive-security / red-team tool intended for authorized
penetration tests and detection-lab research. Only run it against Active Directory environments
you are explicitly authorized to test.

## Prerequisites

- **`Administrators`-equivalent rights** (or an explicit delegation of read access to
  `CN=Deleted Objects`) on the target domain. Non-privileged accounts cannot see the container at
  all, regardless of which auth method is used — this is an AD-enforced restriction, not something
  GhostHound can work around.
- Network reachability to a Domain Controller on LDAP (389) or LDAPS (636).
- BloodHound CE v8+ if you want to import the resulting graph (collection and JSON output work
  standalone without it).
- To build from source: Rust 1.85 or newer (every crate is on `edition = "2024"`). See
  [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full toolchain and local check setup.

## Usage

```bash
ghosthound -d ghost.local --dc-ip 10.0.0.10 -u alice -o tombstones.json
```

Password resolution order: `--password` (avoid — visible via `ps`/`/proc/<pid>/cmdline` and shell
history), then the `LDAP_PASSWORD` environment variable, then an interactive prompt if neither is
set.

By default GhostHound connects over LDAPS (636) with certificate verification on. Two flags exist
for environments where that doesn't fit:

- `--disable-ldaps` — fall back to cleartext LDAP (389). The bind password is sent in plaintext;
  avoid this against anything but an isolated lab.
- `--insecure-tls` — keep LDAPS (encrypted transport) but skip certificate verification, for
  self-signed/lab certificates that aren't in your trust store. Prefer this over
  `--disable-ldaps` whenever the DC's cert is the only problem.

`--timeout-secs` (default 30) bounds both the initial connection and every subsequent LDAP
operation, so an unreachable DC or a wrong `--dc-ip` fails within that window instead of hanging.

Run `ghosthound --help` for the full flag list.

## Workspace Layout

GhostHound is built as a library-first workspace — see `docs/adr/0001-language-rust-library-first.md`
for the rationale:

- `bloodhound-opengraph`: BloodHound OpenGraph JSON builder (the Rust counterpart to Python's
  `bhopengraph`).
- `ad-secdesc`: permissively-licensed, from-scratch parser for `ntSecurityDescriptor`/DACL/ACEs
  (see `docs/adr/0003-security-descriptor-parsing-strategy.md` for why this isn't a dependency on
  the only existing Rust equivalent, which is GPL-3.0).
- `ad-secdesc-oracle`: internal, unpublished differential test harness comparing `ad-secdesc`
  against that GPL-3.0 crate as a black-box oracle — quarantined out of the default build and
  every published crate's dependency graph.
- `ad-tombstone`: LDAP `SHOW_DELETED` enumeration, AD Recycle Bin state modeling, and
  reanimation-rights analysis.
- `ghosthound`: the CLI orchestrating the above.

## Detected Paths

A `GhostHound_CanReanimate` edge is emitted for two distinct mechanisms, recorded on the edge's
`source` property (the single strongest one) and `sources` property (all of them) — see
`docs/adr/0007-ownership-and-dacl-reanimation-paths.md`:

| `source` | Meaning |
| --- | --- |
| `reanimate_right` | The principal formally holds the Reanimate-Tombstones control access right (GUID `45ec5156-db7e-47bb-b53f-dbeb2d03c40f`): either domain-wide, from the naming-context root's DACL (where an unscoped control-access/`GenericAll` grant also implies it), or from an ACE on the tombstone naming that GUID explicitly — typically inherited from `CN=Deleted Objects`. |
| `owner` | The principal is the tombstone's owner (`OwnerSid` of its own `nTSecurityDescriptor`). An owner can rewrite the object's DACL regardless of what that DACL says. |
| `write_dac` | The principal holds `WRITE_DAC` on the tombstone and can grant itself the right. `GenericAll` on the tombstone lands here (plus `write_owner`), *not* under `reanimate_right`: Reanimate-Tombstones is validated at the naming-context root, so broad rights on the object itself buy the ACL rewrite, not the right. |
| `write_owner` | The principal holds `WRITE_OWNER` on the tombstone, can take ownership, and thereby obtain `WRITE_DAC`. |

The distinction is operational, not cosmetic: `reanimate_right` is ready to use as-is, while the
other three need a DACL/owner rewrite on the tombstone first — an extra step that leaves an
auditable trace. Filter on `source` (or `'write_dac' IN e.sources`) when that matters. Each
principal gets one edge per tombstone no matter how many mechanisms qualify it; the tombstone node
also carries its owner as an `ownersid` property.

Reading a tombstone's own descriptor needs `READ_CONTROL` on that object, and the `SD_FLAGS` LDAP
control (`1.2.840.113556.1.4.801`, requesting `OWNER|GROUP|DACL` only) — without it the DC would try
to hand back the SACL too, which needs `SeSecurityPrivilege`, and drops `nTSecurityDescriptor` from
the response entirely instead. When a descriptor still isn't readable, GhostHound says so on stderr
rather than reporting the tombstone as uncontrolled.

Well-known principals (BUILTIN groups, `SYSTEM`, Authenticated Users) are emitted domain-scoped as
`<DOMAIN FQDN>-<SID>`, matching how SharpHound/RustHound-CE store their `objectid` — otherwise their
placeholder nodes share no `objectid` with any real node and `bridge_shadow_nodes.cypher` can't pair
them.

## Importing into BloodHound

1. In BloodHound CE's OpenGraph Management page, upload `crates/ad-tombstone/model.json` once to
   register the `GhostHound_TombstoneUser`/`GhostHound_TombstoneComputer`/`GhostHound_TombstoneGroup`
   node kinds and the `GhostHound_CanReanimate`/`GhostHound_WasMemberOf`/`GhostHound_SameAs`
   relationship kinds (all registered as traversable, so they participate in shortest-path
   queries).
2. Upload the JSON GhostHound produced (via the UI or the ingest API) as a normal OpenGraph data
   payload.
3. Run `crates/ad-tombstone/bridge_shadow_nodes.cypher` directly against Neo4j (BloodHound CE's
   own Cypher search bar is read-only and will reject it):
   ```bash
   docker exec -i <graph-db-container> cypher-shell -u neo4j -p <password> < crates/ad-tombstone/bridge_shadow_nodes.cypher
   ```
   GhostHound's edges to existing AD principals (Domain Admins, etc.) land on placeholder nodes
   rather than the real ones BloodHound already has — an OpenGraph ingest limitation, not a bug in
   this data; see `docs/adr/0006-opengraph-cross-source-node-identity.md`. This script bridges
   them so paths are actually traversable. Safe to re-run after every import.
4. Import the starter queries in `crates/ad-tombstone/queries/`. BloodHound CE's saved-query import
   takes **one query per JSON file** (`{name, description, query}`), or a ZIP of such files — so zip
   the directory and upload that in one go:
   ```bash
   (cd crates/ad-tombstone/queries && zip -X ../ghosthound-queries.zip *.json)
   ```
   Then, in the Cypher search panel, use the import control (it accepts `application/json` and
   `application/zip`). Individual `.json` files can also be imported one at a time. Note this is
   *not* BloodHound Legacy's single-file `customqueries.json` format — CE's
   `POST /api/v2/saved-queries/import` unmarshals each file into one query and rejects an array or a
   `{"queries": [...]}` wrapper.
5. Optionally run `crates/ad-tombstone/privilege_zones.cypher` once to tag tombstones under Tier Zero
   OUs as high-value — this also needs `cypher-shell` rather than the search bar, for the same reason
   as step 3 (its `SET` is an updating clause too).

Once bridged, the reanimation path renders as a normal traversable path — a tombstone that was
a Domain Admins member before deletion, reachable by every principal with the Reanimate-Tombstones
right, bridged into the real Domain Admins node:

![GhostHound reanimation path from a homelab test run: several principals with GhostHound_CanReanimate rights point to a tombstoned user, which has a GhostHound_WasMemberOf edge to a placeholder node, bridged via GhostHound_SameAs into the real Domain Admins group.](docs/img/reanimation-path-example.png)

## Supply-Chain Posture

This project prioritizes high-confidence security from day 1 (`docs/adr/0005-supply-chain-openssf-posture.md`):

- `cargo deny` for strict copyleft/GPL bans and vulnerability auditing.
- OpenSSF Scorecard workflows.
- `cargo fuzz` for panic safety in parsing raw binary descriptors.
- No `unsafe` in foundational libraries.

## Credits

Built by **JVBotelho** — [glitchedcat.com](https://glitchedcat.com).

GhostHound is MIT OR Apache-2.0 licensed, so you are free to use, modify, and embed it without
asking. If it turns up something useful on an engagement or in research, a link back is appreciated
but never required. `CITATION.cff` has ready-made citation metadata (GitHub renders it as the
"Cite this repository" button).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the toolchain, the local checks CI enforces, and the
dependency rules. Security vulnerabilities go through the private process in
[`SECURITY.md`](SECURITY.md), not public issues.

## Design Rationale

The `docs/adr/` directory records the decisions behind this design (language choice, auth scope,
the `ad-secdesc` licensing constraint, the AD Recycle Bin data model, supply-chain posture), and
`docs/research/tombstone-viability-findings.md` has the underlying research.
