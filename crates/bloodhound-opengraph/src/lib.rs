//! A builder for [BloodHound](https://github.com/SpecterOps/BloodHound) OpenGraph JSON payloads
//! — the Rust counterpart to Python's `bhopengraph`.
//!
//! BloodHound CE v8+ ingests custom attack-path graphs from third-party collectors as a JSON
//! payload of `{metadata, graph: {nodes, edges}}`, separate from the one-time `model.json`
//! extension-definition schema that registers your node/edge kinds. This crate builds that JSON
//! *data* payload; it has no domain-specific knowledge of Active Directory, Azure, or any
//! particular attack surface. Start at [`OpenGraphBuilder`].

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// The `metadata` block of an OpenGraph payload: which collector/source produced this data.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OpenGraphMetadata {
    /// Identifies the ingest source. BloodHound scopes node/relationship identity to this value
    /// for anything not otherwise resolved -- see [`EdgeEndpoint::by_property`]'s caveat.
    pub source_kind: String,
}

/// The `graph` block of an OpenGraph payload: the nodes and edges themselves.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OpenGraphGraph {
    /// Nodes in this payload. Omitted from the serialized JSON entirely if empty.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub nodes: Vec<Node>,
    /// Edges in this payload. Omitted from the serialized JSON entirely if empty.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub edges: Vec<Edge>,
}

/// A full OpenGraph ingest payload: `{metadata, graph}`. Build one via
/// [`OpenGraphBuilder::build`] rather than constructing this directly.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OpenGraphData {
    /// Which source produced this payload.
    pub metadata: OpenGraphMetadata,
    /// The nodes and edges themselves.
    pub graph: OpenGraphGraph,
}

/// A node in the graph.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Node {
    /// The node's unique identifier, referenced by [`EdgeEndpoint::new`] elsewhere in the same
    /// payload.
    pub id: String,
    /// The node's kind(s) -- must match a `node_kinds[].name` registered in the extension's
    /// `model.json` (for a custom kind) or a BloodHound base kind (`Group`, `User`, etc.). A kind
    /// that doesn't match any registered `node_kinds.name` is dropped from the structured graph
    /// on import.
    pub kinds: Vec<String>,
    /// Arbitrary properties displayed on the node. Omitted from the serialized JSON entirely if
    /// empty.
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub properties: HashMap<String, Value>,
}

/// One `key`/`operator`/`value` condition used by [`EdgeEndpoint::by_property`] to resolve a node.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PropertyMatcher {
    /// The node property to compare against.
    pub key: String,
    /// The comparison operator. BloodHound's ingest schema only accepts `"equals"` here --
    /// `"equals_ignore_case"` is a real operator BloodHound's Go code recognizes internally, but
    /// the JSON schema that validates incoming `property_matchers` rejects it outright (confirmed
    /// against a live instance: using it fails ingest with a schema-validation error, not a
    /// silent fallback to case-sensitive matching).
    pub operator: String,
    /// The value to compare `key` against.
    pub value: Value,
}

/// One endpoint (start or end) of an [`Edge`]. Construct via [`EdgeEndpoint::new`] (match by raw
/// ID) or [`EdgeEndpoint::by_property`] (match by kind + property lookup).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EdgeEndpoint {
    /// The ID to match by, when `match_by == "id"`. Empty (and omitted from the serialized JSON)
    /// when using [`EdgeEndpoint::by_property`] instead.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub value: String,
    /// An optional kind constraint the matched node must satisfy.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kind: Option<String>,
    /// The match strategy: `"id"` or `"property"`.
    pub match_by: String,
    /// The conditions to match by, when `match_by == "property"`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub property_matchers: Option<Vec<PropertyMatcher>>,
}

/// A relationship between two nodes.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Edge {
    /// The relationship kind -- must match a `relationship_kinds[].name` registered in the
    /// extension's `model.json` (for a custom kind) or a BloodHound base kind. Set
    /// `is_traversable: true` on the registered kind if it should participate in
    /// shortest-path/attack-path queries.
    pub kind: String,
    /// The source endpoint of the relationship.
    pub start: EdgeEndpoint,
    /// The target endpoint of the relationship.
    pub end: EdgeEndpoint,
    /// Arbitrary properties on the edge itself. Omitted from the serialized JSON entirely if
    /// empty.
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub properties: HashMap<String, Value>,
}

/// Accumulates nodes and edges, then produces a complete [`OpenGraphData`] payload via
/// [`OpenGraphBuilder::build`].
///
/// ```
/// use bloodhound_opengraph::{Node, OpenGraphBuilder};
///
/// let mut builder = OpenGraphBuilder::new();
/// builder.add_node(Node::new("S-1-5-21-...-1105", "MyExtension_User"));
/// let payload = builder.build("MyExtension");
/// assert_eq!(payload.metadata.source_kind, "MyExtension");
/// ```
pub struct OpenGraphBuilder {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
}

impl Default for OpenGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenGraphBuilder {
    /// Starts an empty builder.
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }

    /// Adds a node to the payload.
    pub fn add_node(&mut self, node: Node) -> &mut Self {
        self.nodes.push(node);
        self
    }

    /// Adds an edge to the payload.
    pub fn add_edge(&mut self, edge: Edge) -> &mut Self {
        self.edges.push(edge);
        self
    }

    /// Consumes the builder and produces the final payload, stamping `source_kind` into
    /// `metadata`.
    pub fn build(self, source_kind: impl Into<String>) -> OpenGraphData {
        OpenGraphData {
            metadata: OpenGraphMetadata {
                source_kind: source_kind.into(),
            },
            graph: OpenGraphGraph {
                nodes: self.nodes,
                edges: self.edges,
            },
        }
    }
}

impl Node {
    /// Creates a node with a single initial kind. Add more via [`Node::add_kind`].
    pub fn new(id: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            kinds: vec![kind.into()],
            properties: HashMap::new(),
        }
    }

    /// Adds an additional kind to the node (a node may have more than one).
    pub fn add_kind(&mut self, kind: impl Into<String>) -> &mut Self {
        self.kinds.push(kind.into());
        self
    }

    /// Sets a property on the node, overwriting any existing value for `key`.
    pub fn add_property(&mut self, key: impl Into<String>, value: impl Into<Value>) -> &mut Self {
        self.properties.insert(key.into(), value.into());
        self
    }
}

impl EdgeEndpoint {
    /// Matches a node by its raw ID (`match_by: "id"`) -- the node must already be known by that
    /// ID, either because this payload declares it in its own `nodes` list, or because it's
    /// otherwise resolvable within the ingest's own source (see [`EdgeEndpoint::by_property`]'s
    /// caveat for referencing nodes from a *different* source).
    pub fn new(value: impl Into<String>, match_by: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            kind: None,
            match_by: match_by.into(),
            property_matchers: None,
        }
    }

    /// Matches a node by kind + property equality instead of a raw ID reference, letting
    /// BloodHound resolve the node's real ID via a database lookup rather than the caller needing
    /// to already know it.
    ///
    /// This does not, by itself, let a relationship attach to a node from a different ingest
    /// source (e.g. a base AD `Group` node SharpHound/RustHound-CE already created): BloodHound
    /// scopes relationship-endpoint node identity to the ingest's own source kind regardless of
    /// match strategy, so specifying an existing base kind here still creates a new node under
    /// that identity -- which collides with BloodHound's own uniqueness constraint on that kind
    /// and fails the whole ingest (verified against a live instance; see
    /// docs/adr/0006-opengraph-cross-source-node-identity.md).
    pub fn by_property(
        kind: impl Into<String>,
        key: impl Into<String>,
        operator: impl Into<String>,
        value: Value,
    ) -> Self {
        Self {
            value: String::new(),
            kind: Some(kind.into()),
            match_by: "property".to_string(),
            property_matchers: Some(vec![PropertyMatcher {
                key: key.into(),
                operator: operator.into(),
                value,
            }]),
        }
    }
}

impl Edge {
    /// Creates an edge of the given kind between two endpoints.
    pub fn new(source: EdgeEndpoint, target: EdgeEndpoint, kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            start: source,
            end: target,
            properties: HashMap::new(),
        }
    }

    /// Sets a property on the edge, overwriting any existing value for `key`.
    pub fn add_property(&mut self, key: impl Into<String>, value: impl Into<Value>) -> &mut Self {
        self.properties.insert(key.into(), value.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_builder() {
        let mut builder = OpenGraphBuilder::new();
        let mut node = Node::new("S-1-5-21-123", "User");
        node.add_property("name", json!("TEST_USER"));

        builder.add_node(node);
        let data = builder.build("GhostHound");

        assert_eq!(data.graph.nodes.len(), 1);
        assert_eq!(data.metadata.source_kind, "GhostHound");
        assert_eq!(data.graph.nodes[0].id, "S-1-5-21-123");
    }
}
