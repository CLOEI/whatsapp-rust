use chrono::Local;
use log::{debug, error, info, warn};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use wacore::proto_helpers::MessageExt;
use wacore::types::events::Event;
use whatsapp_rust::bot::Bot;
use whatsapp_rust::pair_phone::PairClientType;
use whatsapp_rust::store::SqliteStore;
use whatsapp_rust::store::traits::Backend;
use whatsapp_rust_tokio_transport::TokioWebSocketTransportFactory;
use whatsapp_rust_ureq_http_client::UreqHttpClient;

/// A minimal, listen-only bot designed for debugging.
/// It connects, logs in, and prints detailed information for every event.
/// This bot will now act as a receiver to debug messages sent from other clients.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info,whatsapp_rust=debug,wacore=debug"),
    )
    .format(|buf, record| {
        use std::io::Write;
        writeln!(
            buf,
            "{} [{:<5}] [{}] - {}",
            Local::now().format("%H:%M:%S"),
            record.level(),
            record.target(),
            record.args()
        )
    })
    .init();

    info!("--- Starting Listen-Only Debugging Bot ---");

    let backend = Arc::new(
        SqliteStore::new("listener.db")
            .await
            .expect("Failed to create listener backend"),
    ) as Arc<dyn Backend>;

    let transport_factory = TokioWebSocketTransportFactory::new();
    let http_client = UreqHttpClient::new();

    // Safeguard to ensure pair_phone is only called once
    let pair_phone_invoked = Arc::new(AtomicBool::new(false));

    let mut bot = Bot::builder()
        .with_backend(backend)
        .with_transport_factory(transport_factory)
        .with_http_client(http_client)
        .on_event({
            let pair_phone_invoked = pair_phone_invoked.clone();
            move |event, client| {
                let pair_phone_invoked = pair_phone_invoked.clone();
                async move {
                    match event {
                        Event::PairingQrCode { code, timeout } => {
                            info!("--- Pairing QR Code (valid for {}s) ---", timeout.as_secs());
                            println!("\n{}\n", code); // Use println to make it easy to copy
                            info!("-------------------------------------------------");

                            // Invoke pair_phone only on the first PairingQrCode event
                            if !pair_phone_invoked.swap(true, Ordering::SeqCst) {
                                info!("🔐 First pairing event - attempting phone pairing...");
                                let phone_number = "62813147890";

                                match client
                                    .pair_phone(
                                        phone_number,
                                        true, // show push notification
                                        PairClientType::Chrome,
                                        "Chrome (Linux)",
                                    )
                                    .await
                                {
                                    Ok(pairing_code) => {
                                        info!("===========================================");
                                        info!("📱 Pairing code: {}", pairing_code);
                                        info!("===========================================");
                                        info!("Enter this code on your phone:");
                                        info!("1. Open WhatsApp on your phone");
                                        info!("2. Go to Settings > Linked Devices");
                                        info!("3. Tap 'Link a Device'");
                                        info!("4. Tap 'Link with phone number instead'");
                                        info!("5. Enter the code: {}", pairing_code);
                                        info!("===========================================");
                                    }
                                    Err(e) => {
                                        error!("Failed to generate pairing code: {:?}", e);
                                        info!("You can still scan the QR code above as fallback");
                                    }
                                }
                            } else {
                                info!("⏭️  Skipping pair_phone (already invoked once)");
                            }
                        }
                        Event::PairSuccess(success) => {
                            info!("✅ Successfully paired with phone!");
                            info!("   Device ID: {}", success.id);
                            info!("   Business name: {}", success.business_name);
                            info!("   Platform: {}", success.platform);
                        }
                        Event::PairError(error) => {
                            error!("❌ Pairing failed: {}", error.error);
                        }
                        Event::Connected(_) => {
                            info!("[EVENT] ✅ Connected successfully!");

                            // Test is_on_whatsapp functionality
                            match client.is_on_whatsapp(&["0813147890".to_string()]).await {
                                Ok(responses) => {
                                    info!("=== IsOnWhatsApp Results ===");
                                    for response in responses {
                                        info!("  Phone: {}", response.query);
                                        info!("  JID: {}", response.jid);
                                        info!("  Registered: {}", response.is_in);
                                        if let Some(verified) = response.verified_name {
                                            info!("  Verified Business:");
                                            if let Some(name) = verified.details.verified_name {
                                                info!("    Name: {}", name);
                                            }
                                            if let Some(issuer) = verified.details.issuer {
                                                info!("    Issuer: {}", issuer);
                                            }
                                            if let Some(serial) = verified.details.serial {
                                                info!("    Serial: {}", serial);
                                            }
                                        } else {
                                            info!("  Not a verified business");
                                        }
                                        info!("===========================");
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to check is_on_whatsapp: {}", e);
                                }
                            }
                        }
                        Event::Message(msg, info) => {
                            let text = msg.text_content().unwrap_or("<media or empty>");
                            info!(
                                "[EVENT] 📩 Message Received from {}: '{}'",
                                info.source.sender, text
                            );
                            debug!("[EVENT] Full Message Info: {:?}", info);
                            debug!("[EVENT] Full Message Content: {:?}", msg);
                        }
                        Event::Receipt(receipt) => {
                            info!(
                                "[EVENT] 📨 Receipt Received for {:?}, type: {:?}",
                                receipt.message_ids, receipt.r#type
                            );
                        }
                        Event::LoggedOut(logout_info) => {
                            error!("[EVENT] ❌ Logged out! Reason: {:?}", logout_info.reason);
                        }
                        Event::UndecryptableMessage(info) => {
                            warn!(
                                "[EVENT] ❗ UNDECRYPTABLE MESSAGE from {}: {:?}",
                                info.info.source.sender, info
                            );
                        }
                        _ => {
                            debug!("[EVENT] 📢 Other Event: {:?}", event);
                        }
                    }
                }
            }
        })
        .build()
        .await
        .expect("Failed to build listener bot");

    info!("🤖 Listener bot built. Starting run loop...");
    let bot_handle = bot.run().await.expect("Failed to start listener bot");

    #[cfg(feature = "signal")]
    tokio::select! {
        result = bot_handle => {
            if let Err(e) = result {
                error!("Listener bot ended with error: {}", e);
            } else {
                info!("Listener bot ended gracefully");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("🛑 Received Ctrl+C, shutting down listener...");
        }
    }

    #[cfg(not(feature = "signal"))]
    tokio::select! {
        result = bot_handle => {
            if let Err(e) = result {
                error!("Listener bot ended with error: {}", e);
            } else {
                info!("Listener bot ended gracefully");
            }
        }
    }

    Ok(())
}
