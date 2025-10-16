# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A high-performance, asynchronous Rust library for interacting with the WhatsApp platform. This project implements the WhatsApp Web protocol with full E2E encryption (Signal Protocol), media handling, and multi-device support. It's runtime-agnostic and storage-agnostic through trait-based abstractions.

## Build & Test Commands

### Building
```bash
# Build the main project
cargo build

# Build with specific features (default includes sqlite-storage, tokio-transport, ureq-client, tokio-native)
cargo build --no-default-features --features "sqlite-storage,tokio-transport"

# Build release version (optimized for size)
cargo build --release

# Build specific workspace member
cargo build -p wacore
cargo build -p waproto
cargo build -p whatsapp-rust-sqlite-storage
```

### Testing
```bash
# Run all tests
cargo test --all

# Run tests for specific crate
cargo test -p wacore

# Run specific test by name
cargo test noise_handshake

# Run tests in a specific file
cargo test --test binary_protocol_test
```

### Running Examples
```bash
# Run the main ping-pong bot (src/main.rs)
cargo run

# Run multi-account example
cargo run --example multi_account

# Run listen-only example
cargo run --example listen_only
```

### Code Quality
```bash
# Format code
cargo fmt

# Run linter
cargo clippy --all-targets

# Check without building
cargo check
```

## Workspace Architecture

This is a multi-crate Rust workspace with clear separation of concerns:

### Core Crates
- **whatsapp-rust** (root): High-level client API, orchestration, Bot builder pattern
- **wacore**: Platform-agnostic protocol implementation (handshake, encryption, state management traits)
- **waproto**: Protocol buffer definitions generated from `.proto` files via prost
- **wacore/binary**: Binary protocol handling (node marshaling/unmarshaling, JID parsing)

### Pluggable Implementation Crates
- **storages/sqlite-storage**: SQLite backend implementation (default)
- **transports/tokio-transport**: Tokio WebSocket transport (default)
- **http_clients/ureq-client**: Blocking HTTP client for media operations (default)

The pluggable architecture allows swapping implementations via features:
```rust
// Custom implementations possible for:
- Backend trait (PostgreSQL, MongoDB, Redis, browser storage, etc.)
- Transport trait (async-std, WASM, custom protocols)
- HttpClient trait (different HTTP libraries or runtimes)
```

## Critical Architecture Patterns

### 1. State Management
**NEVER modify Device state directly.** Use the command pattern:

```rust
// ❌ WRONG - Direct mutation
device.write().await.identity_key = new_key;

// ✅ CORRECT - Via commands
use whatsapp_rust::store::commands::DeviceCommand;
persistence_manager.process_command(DeviceCommand::SetIdentityKey(new_key)).await?;

// For read-only access:
let device_snapshot = persistence_manager.get_device_snapshot().await;
```

This ensures atomic, auditable state changes and proper persistence.

### 2. Chat-Level Locking
To prevent race conditions, all message processing for a specific chat is serialized:

```rust
// Client has per-chat locks (DashMap<Jid, Arc<Mutex<()>>>)
let mutex_arc = client.chat_locks
    .entry(chat_jid)
    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
    .clone();
let _lock_guard = mutex_arc.lock().await;
// Now safe to process messages from this chat
```

This is critical in [src/message.rs](src/message.rs) for message decryption handlers.

### 3. Dual JID System (LID vs Phone Number)
WhatsApp has two identity systems:
- **LID (Lightweight Identity)**: Format `236395184570386.1:75@lid` - used for display and group sender keys
- **Phone Number (PN)**: Format `1234567890@s.whatsapp.net` - used for 1-on-1 Signal sessions

**Key rule**:
- Use **display JID (LID)** for sender key lookups in group messages
- Use **encryption JID (phone number)** for Signal Protocol session decryption
- Messages include both in attributes: `participant_lid` and `participant_pn`

Implementation is in [src/message.rs](src/message.rs) `handle_encrypted_message()`.

### 4. Signal Protocol Message Flow
Two-pass decryption for group messages:

**Pass 1 - Session Encryption** (`pkmsg`/`msg` nodes):
```rust
// 1. Parse PreKeySignalMessage or SignalMessage
// 2. Decrypt using Signal Protocol session (1-on-1 E2E)
// 3. Handle special cases:
//    - DuplicatedMessage: Expected during reconnect, skip skmsg processing
//    - UntrustedIdentity: Identity changed, delete old identity and retry
//    - SessionNotFound: Graceful failure (e.g., LID without session)
```

**Pass 2 - Group Encryption** (`skmsg` nodes):
```rust
// 1. Decrypt using sender key (group E2E)
// 2. Use display JID (LID) for sender key lookup
// 3. Handle SenderKeyDistributionMessage (SKDM) separately
```

See [src/message.rs](src/message.rs) `process_session_enc_batch()` and `process_group_enc_batch()`.

### 5. Async Runtime & Blocking Operations
All I/O is Tokio-based. **Critical**: Blocking operations must use `spawn_blocking`:

```rust
// ❌ WRONG - Blocks async runtime
let response = ureq::get(url).call()?;

// ✅ CORRECT - Offload to thread pool
let response = tokio::task::spawn_blocking(move || {
    ureq::get(url).call()
}).await??;
```

This applies to:
- All `ureq` HTTP calls ([src/download.rs](src/download.rs), [src/upload.rs](src/upload.rs))
- Heavy encryption/decryption operations
- Any CPU-intensive processing

## Message Processing Pipeline

```
WebSocket Transport
    ↓
Frame Decoder (src/framing.rs)
    ↓
Noise Decryption (src/socket/noise_socket.rs)
    ↓
Binary Unmarshal (wacore-binary)
    ↓
Stanza Router (src/handlers/router.rs)
    ↓
Handler Dispatch by tag:
    ├─ "message" → MessageHandler → handle_encrypted_message()
    │   ├─ Acquire chat lock
    │   ├─ Decrypt session encryption (pkmsg/msg)
    │   ├─ Decrypt group encryption (skmsg)
    │   ├─ Parse protobuf (wa::Message)
    │   ├─ Process special messages (SKDM, app state keys)
    │   ├─ Dispatch Event::Message
    │   └─ Send delivery receipt (async)
    ├─ "iq" → IqHandler
    ├─ "receipt" → ReceiptHandler
    └─ "notification" → NotificationHandler
    ↓
Event Bus (client.event_bus)
    ↓
User Application
```

## Storage Backend Implementation

To implement a custom storage backend:

1. Implement the composite `Backend` trait from `wacore::store::traits`:
```rust
pub trait Backend:
    IdentityStore           // Signal identity keys
    + SessionStore          // Signal sessions
    + AppStateKeyStore      // App state sync keys
    + AppStateStore         // App state mutations
    + PreKeyStore           // Pre-keys for X3DH
    + SignedPreKeyStore     // Signed pre-keys
    + SenderKeyStoreHelper  // Group sender keys
    + DevicePersistence     // Device data
    + Send + Sync
{}
```

2. See [examples/custom_backend_example.rs](examples/custom_backend_example.rs) for complete implementation template.

3. Key methods to implement correctly:
   - `DevicePersistence::load_device_data()` - Called on startup
   - `DevicePersistence::save_device_data()` - Called after state changes
   - `SessionStore::get_session()` / `put_session()` - Performance critical
   - `IdentityStore::is_trusted_identity()` - Security critical

Reference implementation: [storages/sqlite-storage/](storages/sqlite-storage/)

## Media Handling

### Downloads
```rust
use wacore::download::{Downloadable, MediaType};

// Generic download via Downloadable trait
client.download_to_file(media_message, &mut file_writer).await?;

// Process:
// 1. Check MediaConn expiry, refresh if needed (src/mediaconn.rs)
// 2. Download encrypted file from WhatsApp CDN
// 3. Decrypt using media_key (AES-256-CBC + HMAC-SHA256 verification)
// 4. Write plaintext to destination
```

### Uploads
```rust
let upload_response = client.upload(plaintext_bytes, MediaType::Image).await?;

// Returns UploadResponse with:
// - url, direct_path
// - media_key, file_enc_sha256, file_sha256
// - file_length
// Use these fields to construct message protobuf
```

Both implemented in [src/download.rs](src/download.rs) and [src/upload.rs](src/upload.rs).

## Event System

The client uses an event bus pattern:

```rust
Bot::builder()
    .on_event(|event, client| async move {
        match event {
            Event::Message(msg, info) => { /* Handle message */ }
            Event::Connected(_) => { /* Connection established */ }
            Event::PairingQrCode { code, timeout } => { /* Show QR */ }
            Event::Receipt(receipt) => { /* Message status update */ }
            Event::UndecryptableMessage { .. } => { /* Decryption failed */ }
            Event::LoggedOut(_) => { /* Session invalidated */ }
            _ => {}
        }
    })
    .build()
```

Events are dispatched from various handlers. Key locations:
- [src/handlers/message.rs](src/handlers/message.rs) - `Event::Message`
- [src/client.rs](src/client.rs) - `Event::Connected`, `Event::Disconnected`
- [src/pair.rs](src/pair.rs) - `Event::PairingQrCode`
- [src/handlers/receipt.rs](src/handlers/receipt.rs) - `Event::Receipt`

## Key Files Reference

**Core Client Files:**
- [src/client.rs](src/client.rs) - Main client orchestration (~1700 lines)
- [src/bot.rs](src/bot.rs) - High-level Bot builder pattern
- [src/handlers/router.rs](src/handlers/router.rs) - Stanza routing
- [src/message.rs](src/message.rs) - Message decryption pipeline
- [src/send.rs](src/send.rs) - Message encryption and sending

**Protocol Implementation:**
- [wacore/src/handshake/](wacore/src/handshake/) - Noise Protocol handshake
- [wacore/src/libsignal/](wacore/src/libsignal/) - Signal Protocol (custom Rust implementation)
- [wacore/binary/src/](wacore/binary/src/) - Binary protocol marshaling
- [waproto/src/whatsapp.proto](waproto/src/whatsapp.proto) - Protobuf definitions

**Storage:**
- [src/store/persistence_manager.rs](src/store/persistence_manager.rs) - State management gatekeeper
- [wacore/src/store/traits.rs](wacore/src/store/traits.rs) - Backend trait definitions
- [storages/sqlite-storage/](storages/sqlite-storage/) - SQLite implementation

**Media:**
- [src/download.rs](src/download.rs) - Media download with decryption
- [src/upload.rs](src/upload.rs) - Media upload with encryption
- [src/mediaconn.rs](src/mediaconn.rs) - Media server connection management
- [wacore/src/download.rs](wacore/src/download.rs) - Downloadable trait definition

**Transport:**
- [src/transport.rs](src/transport.rs) - Transport abstraction
- [src/socket/noise_socket.rs](src/socket/noise_socket.rs) - Noise encryption layer
- [transports/tokio-transport/](transports/tokio-transport/) - Tokio WebSocket implementation

## Testing Strategy

### Unit Tests
Located in same file as implementation:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    // Test individual functions/structs
}
```

### Integration Tests
Located in `wacore/tests/`:
- `noise_handshake_test.rs` - Handshake protocol tests
- `binary_protocol_test.rs` - Binary marshaling tests
- `jid_test.rs` - JID parsing tests
- `appstate_mac_test.rs` - App state MAC verification tests

### Running Specific Tests
```bash
# Test a module
cargo test --lib client::tests

# Test with output
cargo test -- --nocapture

# Test single function
cargo test test_jid_parsing
```

## Common Development Patterns

### Adding a New Message Type Handler

1. Check if protobuf definition exists in [waproto/src/whatsapp.proto](waproto/src/whatsapp.proto)
2. Add handling in [src/message.rs](src/message.rs) `handle_decrypted_plaintext()`
3. Define new Event variant if needed
4. Dispatch event via `client.event_bus.dispatch()`

### Adding a New IQ Request Type

1. Define request builder in [src/request.rs](src/request.rs) or relevant module
2. Send via `client.send_iq()` - returns awaitable response
3. Handle response in [src/handlers/iq.rs](src/handlers/iq.rs) if special processing needed

### Implementing Reconnection Logic

The client handles reconnection automatically in [src/client.rs](src/client.rs) `run()` loop. Key points:
- Transport disconnect triggers reconnection attempt
- Exponential backoff implemented in keepalive loop
- Device state persisted between reconnections
- No need for manual reconnection in user code

## Security Considerations

### Identity Key Trust
The `IdentityStore::is_trusted_identity()` implementation is security-critical:
- First contact: Always trust (TOFU - Trust On First Use)
- Subsequent contacts: Verify unchanged or explicitly mark as trusted
- Identity key changes should trigger `UntrustedIdentity` error
- Implementation must handle both sending and receiving directions

### Session Cleanup on Identity Change
When identity keys change:
```rust
// Clear old sessions and identity
device.backend.delete_identity(&address.to_string()).await;
device.backend.delete_session(&address.to_string()).await;
// Then retry with new identity
```

See [src/message.rs](src/message.rs) `process_session_enc_batch()` error handling.

## Debugging Tips

### Enable Detailed Logging
```rust
env_logger::Builder::from_env(
    env_logger::Env::default().default_filter_or("debug")
).init();

// Specific module logging:
// RUST_LOG=whatsapp_rust::message=trace cargo run
```

### Inspect Binary Protocol
```rust
use wacore_binary::Node;

// Pretty-print nodes for debugging
log::debug!("Received node: {:#?}", node);
```

### Check Signal Protocol State
```rust
// Session existence
let has_session = device.backend.get_session(&address).await?.is_some();

// Identity key for address
let identity = device.backend.load_identity(&address).await?;
```

## Reference Projects

This implementation is based on:
- **whatsmeow** (Go): https://github.com/tulir/whatsmeow - Primary reference for protocol details
- **Baileys** (TypeScript): https://github.com/WhiskeySockets/Baileys - Additional protocol insights

When protocol behavior is unclear, check whatsmeow implementation first.
