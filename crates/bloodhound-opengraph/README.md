# bloodhound-opengraph

[![Crates.io](https://img.shields.io/crates/v/bloodhound-opengraph.svg)](https://crates.io/crates/bloodhound-opengraph)
[![docs.rs](https://img.shields.io/docsrs/bloodhound-opengraph)](https://docs.rs/bloodhound-opengraph)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/JVBotelho/ghosthound/badge)](https://securityscorecards.dev/viewer/?uri=github.com/JVBotelho/ghosthound)

A Rust builder for [BloodHound](https://github.com/SpecterOps/BloodHound) OpenGraph JSON payloads
— the Rust counterpart to Python's `bhopengraph`.

[BloodHound](https://bloodhound.specterops.io) CE v8+ can ingest arbitrary attack-path graphs from
third-party collectors via **OpenGraph**: a JSON payload of `{metadata, graph: {nodes, edges}}`,
plus a separate `model.json` extension-definition schema that registers your custom node/edge
kinds with BloodHound. This crate builds the *data* payload (the part you generate per collection
run) — it does not generate `model.json`, which is a one-time, hand-authored schema document (see
[GhostHound's](https://github.com/JVBotelho/ghosthound) `model.json` for a worked example).

This crate has no domain-specific knowledge of Active Directory, Azure, or any particular attack
surface — it's a plain, general-purpose OpenGraph builder for any collector you're writing.

## Usage

```rust
use bloodhound_opengraph::{Edge, EdgeEndpoint, Node, OpenGraphBuilder};
use serde_json::json;

let mut builder = OpenGraphBuilder::new();

let mut user = Node::new("S-1-5-21-...-1105", "MyExtension_User");
user.add_property("name", json!("ALICE"));
builder.add_node(user);

let start = EdgeEndpoint::new("S-1-5-21-...-1105", "id");
let end = EdgeEndpoint::new("S-1-5-21-...-512", "id");
builder.add_edge(Edge::new(start, end, "MyExtension_HasAccessTo"));

let payload = builder.build("MyExtension"); // sets metadata.source_kind
let json_output = serde_json::to_string_pretty(&payload)?;
```

### Referencing nodes from another ingest source

`EdgeEndpoint::new(value, "id")` matches a node by its raw ID. `EdgeEndpoint::by_property(kind,
key, operator, value)` instead resolves a node via a database lookup (`match_by: "property"`),
which is what BloodHound's OpenGraph docs describe for referencing nodes your payload didn't
declare itself.

**Caveat, confirmed against a live instance:** this does not by itself let a relationship attach to
a node from a *different* ingest source (e.g. a base Active Directory `Group` node a SharpHound-family
collector already created). BloodHound scopes relationship-endpoint node identity to the ingest's
own source kind regardless of match strategy, so specifying an existing base kind here still
creates a new node under your source's identity — which collides with BloodHound's uniqueness
constraint on that kind and fails the whole ingest. See
[GhostHound's writeup](https://github.com/JVBotelho/ghosthound/blob/main/docs/adr/0006-opengraph-cross-source-node-identity.md)
for the full root-cause analysis and a working bridge-script pattern if you hit this.

## License

MIT OR Apache-2.0.
