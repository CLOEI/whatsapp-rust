use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

/// An event produced by the transport layer.
#[derive(Debug, Clone)]
pub enum TransportEvent {
    /// The transport has successfully connected.
    Connected,
    /// Raw data has been received from the server.
    DataReceived(Bytes),
    /// The connection was lost.
    Disconnected,
}

/// Represents an active network connection.
/// The transport is a dumb pipe for bytes with no knowledge of WhatsApp framing.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Sends raw data to the server.
    async fn send(&self, data: &[u8]) -> Result<(), anyhow::Error>;

    /// Closes the connection.
    async fn disconnect(&self);
}

/// A factory responsible for creating new transport instances.
#[async_trait]
pub trait TransportFactory: Send + Sync {
    /// Creates a new transport and returns it, along with a stream of events.
    async fn create_transport(
        &self,
    ) -> Result<(Arc<dyn Transport>, mpsc::Receiver<TransportEvent>), anyhow::Error>;
}

/// A simple structure to represent an HTTP request
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub url: String,
    pub method: String, // "GET" or "POST"
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

impl HttpRequest {
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            body: None,
        }
    }

    pub fn post(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            method: "POST".to_string(),
            headers: HashMap::new(),
            body: None,
        }
    }

    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }
}

/// A simple structure for the HTTP response
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status_code: u16,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn body_string(&self) -> Result<String> {
        Ok(String::from_utf8(self.body.clone())?)
    }
}

/// Trait for executing HTTP requests in a runtime-agnostic way
#[async_trait]
pub trait HttpClient: Send + Sync {
    /// Executes a given HTTP request and returns the response.
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse>;
}
