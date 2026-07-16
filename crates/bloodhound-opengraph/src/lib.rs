#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OpenGraphMetadata {
    pub source_kind: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OpenGraphGraph {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub nodes: Vec<Node>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub edges: Vec<Edge>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OpenGraphData {
    pub metadata: OpenGraphMetadata,
    pub graph: OpenGraphGraph,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Node {
    pub id: String,
    pub kinds: Vec<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub properties: HashMap<String, Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PropertyMatcher {
    pub key: String,
    pub operator: String,
    pub value: Value,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EdgeEndpoint {
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kind: Option<String>,
    pub match_by: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub property_matchers: Option<Vec<PropertyMatcher>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Edge {
    pub kind: String,
    pub start: EdgeEndpoint,
    pub end: EdgeEndpoint,
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub properties: HashMap<String, Value>,
}

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
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }

    pub fn add_node(&mut self, node: Node) -> &mut Self {
        self.nodes.push(node);
        self
    }

    pub fn add_edge(&mut self, edge: Edge) -> &mut Self {
        self.edges.push(edge);
        self
    }

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
    pub fn new(id: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            kinds: vec![kind.into()],
            properties: HashMap::new(),
        }
    }

    pub fn add_kind(&mut self, kind: impl Into<String>) -> &mut Self {
        self.kinds.push(kind.into());
        self
    }

    pub fn add_property(&mut self, key: impl Into<String>, value: impl Into<Value>) -> &mut Self {
        self.properties.insert(key.into(), value.into());
        self
    }
}

impl EdgeEndpoint {
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
    pub fn new(source: EdgeEndpoint, target: EdgeEndpoint, kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            start: source,
            end: target,
            properties: HashMap::new(),
        }
    }

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
