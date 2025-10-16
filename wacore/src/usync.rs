use anyhow::{anyhow, Result};
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, LEGACY_USER_SERVER};
use wacore_binary::node::{Node, NodeContent};

use crate::types::user::{IsOnWhatsAppResponse, VerifiedName};

pub fn build_get_user_devices_query(jids: &[Jid], sid: &str) -> Node {
    let user_nodes = jids
        .iter()
        .map(|jid| {
            NodeBuilder::new("user")
                .attr("jid", jid.to_non_ad().to_string())
                .build()
        })
        .collect::<Vec<_>>();

    let query_node = NodeBuilder::new("query")
        .children([NodeBuilder::new("devices").attr("version", "2").build()])
        .build();

    let list_node = NodeBuilder::new("list").children(user_nodes).build();

    NodeBuilder::new("usync")
        .attrs([
            ("context", "message"),
            ("index", "0"),
            ("last", "true"),
            ("mode", "query"),
            ("sid", sid),
        ])
        .children([query_node, list_node])
        .build()
}

pub fn parse_get_user_devices_response(resp_node: &Node) -> Result<Vec<Jid>> {
    let list_node = resp_node
        .get_optional_child_by_tag(&["usync", "list"])
        .ok_or_else(|| anyhow!("<usync> or <list> not found in usync response"))?;

    let mut all_devices = Vec::new();

    for user_node in list_node.get_children_by_tag("user") {
        let user_jid = user_node.attrs().jid("jid");
        let device_list_node = user_node
            .get_optional_child_by_tag(&["devices", "device-list"])
            .ok_or_else(|| anyhow!("<device-list> not found for user {user_jid}"))?;

        for device_node in device_list_node.get_children_by_tag("device") {
            let device_id_str = device_node.attrs().string("id");
            let device_id: u16 = device_id_str.parse()?;

            let mut device_jid = user_jid.clone();
            device_jid.device = device_id;
            all_devices.push(device_jid);
        }
    }

    Ok(all_devices)
}

/// Builds a usync query to check if phone numbers are registered on WhatsApp
pub fn build_is_on_whatsapp_query(jids: &[Jid], sid: &str) -> Node {
    let user_nodes = jids
        .iter()
        .map(|jid| {
            NodeBuilder::new("user")
                .attr("jid", jid.to_string())
                .build()
        })
        .collect::<Vec<_>>();

    let query_node = NodeBuilder::new("query")
        .children([
            NodeBuilder::new("business")
                .children([NodeBuilder::new("verified_name").build()])
                .build(),
            NodeBuilder::new("contact").build(),
        ])
        .build();

    let list_node = NodeBuilder::new("list").children(user_nodes).build();

    NodeBuilder::new("usync")
        .attrs([
            ("context", "interactive"),
            ("index", "0"),
            ("last", "true"),
            ("mode", "query"),
            ("sid", sid),
        ])
        .children([query_node, list_node])
        .build()
}

/// Parses the response from is_on_whatsapp query
pub fn parse_is_on_whatsapp_response(resp_node: &Node) -> Result<Vec<IsOnWhatsAppResponse>> {
    let list_node = resp_node
        .get_optional_child_by_tag(&["usync", "list"])
        .ok_or_else(|| anyhow!("<usync> or <list> not found in usync response"))?;

    let mut output = Vec::new();
    let query_suffix = format!("@{}", LEGACY_USER_SERVER);

    for user_node in list_node.get_children_by_tag("user") {
        let jid = user_node.attrs().jid("jid");

        // Parse verified name from business node
        let verified_name = match parse_verified_name(user_node) {
            Ok(vn) => vn,
            Err(e) => {
                log::warn!("Failed to parse verified name for {}: {}", jid, e);
                None
            }
        };

        // Extract contact information
        let contact_node = user_node.get_optional_child_by_tag(&["contact"]);
        let is_in = contact_node
            .map(|node| node.attrs().string("type") == "in")
            .unwrap_or(false);

        // Extract the original query string from contact node content
        let query = match contact_node.and_then(|node| match &node.content {
            Some(NodeContent::Bytes(bytes)) => Some(bytes.as_slice()),
            _ => None,
        }) {
            Some(bytes) => {
                let full_query = String::from_utf8_lossy(bytes);
                full_query.trim_end_matches(&query_suffix).to_string()
            }
            None => jid.user.clone(), // Fallback to JID user part
        };

        output.push(IsOnWhatsAppResponse {
            query,
            jid,
            is_in,
            verified_name,
        });
    }

    Ok(output)
}

/// Parses verified name information from a user node
fn parse_verified_name(user_node: &Node) -> Result<Option<VerifiedName>> {
    use prost::Message;
    use waproto::whatsapp as wa;

    // Get the business node
    let business_node = match user_node.get_optional_child_by_tag(&["business"]) {
        Some(node) => node,
        None => return Ok(None),
    };

    // Get the verified_name node
    let verified_name_node = match business_node.get_optional_child_by_tag(&["verified_name"]) {
        Some(node) => node,
        None => return Ok(None),
    };

    // Extract the certificate bytes from the node content
    let cert_bytes = match &verified_name_node.content {
        Some(NodeContent::Bytes(bytes)) => bytes.as_slice(),
        _ => return Ok(None),
    };

    // Decode the VerifiedNameCertificate protobuf
    let certificate = wa::VerifiedNameCertificate::decode(&cert_bytes[..])
        .map_err(|e| anyhow!("Failed to decode VerifiedNameCertificate: {}", e))?;

    // Decode the nested Details message if present
    let details = match &certificate.details {
        Some(details_bytes) => {
            wa::verified_name_certificate::Details::decode(&details_bytes[..])
                .map_err(|e| anyhow!("Failed to decode Details: {}", e))?
        }
        None => return Ok(None),
    };

    Ok(Some(VerifiedName {
        certificate: Box::new(certificate),
        details: Box::new(details),
    }))
}
