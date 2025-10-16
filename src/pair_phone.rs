use crate::client::Client;
use anyhow::anyhow;
use log::info;
use rand::TryRngCore;
use rand_core::OsRng;
use std::sync::Arc;
use wacore::libsignal::protocol::KeyPair;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::NodeContent;

// Constants for phone pairing
const LINKING_BASE32_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTVWXYZ";
const PBKDF2_ITERATIONS: u32 = 2 << 16; // 131072

/// Client types for pairing with code
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum PairClientType {
    Unknown = 0,
    Chrome = 1,
    Edge = 2,
    Firefox = 3,
    IE = 4,
    Opera = 5,
    Safari = 6,
    Electron = 7,
    UWP = 8,
    OtherWebClient = 9,
}

/// Internal cache for ongoing phone linking process
#[derive(Clone)]
pub(crate) struct PhoneLinkingCache {
    pub jid: Jid,
    pub key_pair: KeyPair,
    pub linking_code: String,
    pub pairing_ref: String,
}

impl Client {
    /// Generates a pairing code that can be used to link to a phone without scanning a QR code.
    ///
    /// You must connect the client normally before calling this (which means you'll also receive a QR code
    /// event, but that can be ignored when doing code pairing). You should also wait for `Event::PairingQrCode`
    /// before calling this to ensure the connection is fully established.
    ///
    /// The exact expiry of pairing codes is unknown, but QR codes are always generated and the login websocket is closed
    /// after the QR codes run out, which means there's a 160-second time limit. It is recommended to generate the pairing
    /// code immediately after connecting to the websocket to have the maximum time.
    ///
    /// # Arguments
    ///
    /// * `phone` - The phone number in international format (without leading +), e.g., "1234567890"
    /// * `show_push_notification` - Whether to show a push notification on the phone
    /// * `client_type` - The type of client (Chrome, Firefox, etc.)
    /// * `client_display_name` - Display name formatted as `Browser (OS)`, e.g., "Chrome (Windows)"
    ///
    /// # Returns
    ///
    /// Returns the pairing code formatted as "XXXX-XXXX" (8 characters with hyphen)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The phone number is too short (≤ 6 digits)
    /// - The phone number starts with 0 (must be in international format)
    /// - The IQ request fails
    /// - The server doesn't return a pairing reference
    pub async fn pair_phone(
        self: &Arc<Self>,
        phone: &str,
        show_push_notification: bool,
        client_type: PairClientType,
        client_display_name: &str,
    ) -> Result<String, anyhow::Error> {
        // Generate ephemeral keypair and linking code
        let (ephemeral_key_pair, ephemeral_key, encoded_linking_code) =
            generate_companion_ephemeral_key()?;

        // Clean phone number
        let phone = phone.chars().filter(|c| c.is_ascii_digit()).collect::<String>();

        // Validate phone number
        if phone.len() <= 6 {
            return Err(anyhow!("Phone number is too short"));
        }
        if phone.starts_with('0') {
            return Err(anyhow!("Phone number must be in international format (no leading 0)"));
        }

        // Construct JID
        let jid = format!("{}@s.whatsapp.net", phone).parse::<Jid>()?;

        // Get companion server auth key
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let companion_server_auth_key_pub = device_snapshot.noise_key.public_key.public_key_bytes();

        // Build and send IQ request
        let link_code_companion_reg = NodeBuilder::new("link_code_companion_reg")
            .attrs([
                ("jid", jid.to_string()),
                ("stage", "companion_hello".to_string()),
                ("should_show_push_notification", show_push_notification.to_string()),
            ])
            .children([
                NodeBuilder::new("link_code_pairing_wrapped_companion_ephemeral_pub")
                    .bytes(ephemeral_key)
                    .build(),
                NodeBuilder::new("companion_server_auth_key_pub")
                    .bytes(companion_server_auth_key_pub.to_vec())
                    .build(),
                NodeBuilder::new("companion_platform_id")
                    .bytes((client_type as i32).to_string().into_bytes())
                    .build(),
                NodeBuilder::new("companion_platform_display")
                    .bytes(client_display_name.as_bytes().to_vec())
                    .build(),
                NodeBuilder::new("link_code_pairing_nonce")
                    .bytes(vec![0])
                    .build(),
            ])
            .build();

        let resp = self
            .send_iq(crate::request::InfoQuery {
                namespace: "md",
                query_type: crate::request::InfoQueryType::Set,
                to: SERVER_JID.parse()?,
                target: None,
                id: None,
                content: Some(NodeContent::Nodes(vec![link_code_companion_reg])),
                timeout: None,
            })
            .await?;

        // Extract pairing ref from response
        let pairing_ref_node = resp
            .get_optional_child_by_tag(&["link_code_companion_reg", "link_code_pairing_ref"])
            .ok_or_else(|| anyhow!("Missing link_code_pairing_ref in response"))?;

        let pairing_ref = match pairing_ref_node.content.as_ref() {
            Some(NodeContent::Bytes(bytes)) => String::from_utf8(bytes.to_vec())?,
            _ => return Err(anyhow!("Unexpected content type in link_code_pairing_ref")),
        };

        // Cache the linking data for later use in notification handler
        let cache = PhoneLinkingCache {
            jid,
            key_pair: ephemeral_key_pair,
            linking_code: encoded_linking_code.clone(),
            pairing_ref,
        };

        *self.phone_linking_cache.lock().await = Some(cache);

        // Format code as XXXX-XXXX
        let formatted_code = format!("{}-{}", &encoded_linking_code[0..4], &encoded_linking_code[4..]);
        info!(target: "Client/PairPhone", "Generated pairing code: {}", formatted_code);

        Ok(formatted_code)
    }
}

/// Generates companion ephemeral key for pairing
fn generate_companion_ephemeral_key() -> Result<(KeyPair, Vec<u8>, String), anyhow::Error> {
    use aes::cipher::{KeyIvInit, StreamCipher};
    use aes::Aes256;
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;
    type Aes256Ctr = ctr::Ctr64BE<Aes256>;

    // Generate ephemeral keypair
    let ephemeral_key_pair = KeyPair::generate(&mut OsRng::unwrap_err(OsRng));

    // Generate random salt, IV, and linking code
    let mut salt = [0u8; 32];
    let mut iv = [0u8; 16];
    let mut linking_code = [0u8; 5];

    OsRng.try_fill_bytes(&mut salt).map_err(|e| anyhow!("Failed to generate salt: {}", e))?;
    OsRng.try_fill_bytes(&mut iv).map_err(|e| anyhow!("Failed to generate IV: {}", e))?;
    OsRng.try_fill_bytes(&mut linking_code).map_err(|e| anyhow!("Failed to generate linking code: {}", e))?;

    // Encode linking code using custom base32 alphabet
    let encoded_linking_code = base32_encode_custom(&linking_code, LINKING_BASE32_ALPHABET);

    // Derive encryption key using PBKDF2
    let mut link_code_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        encoded_linking_code.as_bytes(),
        &salt,
        PBKDF2_ITERATIONS,
        &mut link_code_key,
    );

    // Encrypt the companion public key using AES-256-CTR
    let mut encrypted_pubkey = ephemeral_key_pair.public_key.public_key_bytes().to_vec();
    let mut cipher = Aes256Ctr::new(&link_code_key.into(), &iv.into());
    cipher.apply_keystream(&mut encrypted_pubkey);

    // Concatenate salt + IV + encrypted pubkey
    let mut ephemeral_key = Vec::with_capacity(80);
    ephemeral_key.extend_from_slice(&salt);
    ephemeral_key.extend_from_slice(&iv);
    ephemeral_key.extend_from_slice(&encrypted_pubkey);

    Ok((ephemeral_key_pair, ephemeral_key, encoded_linking_code))
}

/// Custom base32 encoding using WhatsApp's alphabet
fn base32_encode_custom(data: &[u8], alphabet: &str) -> String {
    let alphabet_bytes = alphabet.as_bytes();
    let mut result = String::new();
    let mut bits = 0u32;
    let mut bit_count = 0;

    for &byte in data {
        bits = (bits << 8) | byte as u32;
        bit_count += 8;

        while bit_count >= 5 {
            bit_count -= 5;
            let index = ((bits >> bit_count) & 0x1F) as usize;
            result.push(alphabet_bytes[index] as char);
        }
    }

    // Handle remaining bits
    if bit_count > 0 {
        bits <<= 5 - bit_count;
        let index = (bits & 0x1F) as usize;
        result.push(alphabet_bytes[index] as char);
    }

    result
}

/// Handles the incoming notification for code pair completion
pub(crate) async fn handle_code_pair_notification(
    client: &Arc<Client>,
    node: &wacore_binary::node::Node,
) -> Result<(), anyhow::Error> {
    use aes::cipher::{KeyIvInit, StreamCipher};
    use aes::Aes256;
    use aes_gcm::{Aes256Gcm, KeyInit};
    use aes_gcm::aead::{Aead, Payload};
    use hkdf::Hkdf;
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;
    use wacore::libsignal::protocol::PublicKey;
    type Aes256Ctr = ctr::Ctr64BE<Aes256>;

    let link_cache = match client.phone_linking_cache.lock().await.as_ref() {
        Some(cache) => cache.clone(),
        None => return Err(anyhow!("Received code pair notification without pending pairing")),
    };

    // The notification structure is:
    // <notification>
    //   <link_code_companion_reg>
    //     <link_code_pairing_ref>...</link_code_pairing_ref>
    //     <link_code_pairing_wrapped_primary_ephemeral_pub>...</link_code_pairing_wrapped_primary_ephemeral_pub>
    //     <primary_identity_pub>...</primary_identity_pub>
    //   </link_code_companion_reg>
    // </notification>

    // Get the link_code_companion_reg child node
    let link_code_node = node
        .get_optional_child_by_tag(&["link_code_companion_reg"])
        .ok_or_else(|| anyhow!("Missing link_code_companion_reg node"))?;

    // Validate pairing ref matches
    let link_code_pairing_ref = link_code_node
        .get_optional_child_by_tag(&["link_code_pairing_ref"])
        .and_then(|n| n.content.as_ref())
        .and_then(|c| match c {
            wacore_binary::node::NodeContent::Bytes(b) => Some(b.as_slice()),
            _ => None,
        })
        .ok_or_else(|| anyhow!("Missing link_code_pairing_ref"))?;

    let pairing_ref_str = String::from_utf8(link_code_pairing_ref.to_vec())?;
    if pairing_ref_str != link_cache.pairing_ref {
        return Err(anyhow!("Pairing ref mismatch"));
    }

    // Extract wrapped primary ephemeral pub key
    let wrapped_primary_ephemeral_pub = link_code_node
        .get_optional_child_by_tag(&["link_code_pairing_wrapped_primary_ephemeral_pub"])
        .and_then(|n| n.content.as_ref())
        .and_then(|c| match c {
            wacore_binary::node::NodeContent::Bytes(b) => Some(b.as_slice()),
            _ => None,
        })
        .ok_or_else(|| anyhow!("Missing link_code_pairing_wrapped_primary_ephemeral_pub"))?;

    // Extract primary identity pub key
    let primary_identity_pub = link_code_node
        .get_optional_child_by_tag(&["primary_identity_pub"])
        .and_then(|n| n.content.as_ref())
        .and_then(|c| match c {
            wacore_binary::node::NodeContent::Bytes(b) => Some(b.as_slice()),
            _ => None,
        })
        .ok_or_else(|| anyhow!("Missing primary_identity_pub"))?;

    if primary_identity_pub.len() != 32 {
        return Err(anyhow!("Invalid primary identity pub key length"));
    }

    // Generate random values for ADV secret and key bundle encryption
    let mut adv_secret_random = [0u8; 32];
    let mut key_bundle_salt = [0u8; 32];
    let mut key_bundle_nonce = [0u8; 12];

    OsRng.try_fill_bytes(&mut adv_secret_random)?;
    OsRng.try_fill_bytes(&mut key_bundle_salt)?;
    OsRng.try_fill_bytes(&mut key_bundle_nonce)?;

    // Decrypt primary ephemeral public key
    if wrapped_primary_ephemeral_pub.len() != 80 {
        return Err(anyhow!("Invalid wrapped primary ephemeral pub key length"));
    }

    let primary_salt = &wrapped_primary_ephemeral_pub[0..32];
    let primary_iv = &wrapped_primary_ephemeral_pub[32..48];
    let primary_encrypted_pubkey = &wrapped_primary_ephemeral_pub[48..80];

    // Derive link code key
    let mut link_code_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        link_cache.linking_code.as_bytes(),
        primary_salt,
        PBKDF2_ITERATIONS,
        &mut link_code_key,
    );

    // Decrypt primary public key
    let mut primary_decrypted_pubkey = primary_encrypted_pubkey.to_vec();
    let mut cipher = Aes256Ctr::new(&link_code_key.into(), primary_iv.into());
    cipher.apply_keystream(&mut primary_decrypted_pubkey);

    // Compute ephemeral shared secret using X25519
    let ephemeral_shared_secret = link_cache
        .key_pair
        .private_key
        .calculate_agreement(&PublicKey::from_djb_public_key_bytes(&primary_decrypted_pubkey)?)?;

    // Get our identity key
    let device_snapshot = client.persistence_manager.get_device_snapshot().await;
    let identity_key_pub = device_snapshot.identity_key.public_key.public_key_bytes();
    let identity_key_priv = &device_snapshot.identity_key.private_key;

    // Compute identity shared secret
    let identity_shared_secret = identity_key_priv
        .calculate_agreement(&PublicKey::from_djb_public_key_bytes(primary_identity_pub)?)?;

    // Compute ADV secret using HKDF
    let mut adv_secret_input = Vec::with_capacity(96);
    adv_secret_input.extend_from_slice(&ephemeral_shared_secret);
    adv_secret_input.extend_from_slice(&identity_shared_secret);
    adv_secret_input.extend_from_slice(&adv_secret_random);

    let hk = Hkdf::<Sha256>::new(None, &adv_secret_input);
    let mut adv_secret = [0u8; 32];
    hk.expand(b"adv_secret", &mut adv_secret)
        .map_err(|_| anyhow!("HKDF expand failed for adv_secret"))?;

    // Store ADV secret for later use in pair-success handling
    client
        .persistence_manager
        .process_command(crate::store::commands::DeviceCommand::SetAdvSecretKey(adv_secret))
        .await;

    // Encrypt key bundle
    let hk2 = Hkdf::<Sha256>::new(Some(&key_bundle_salt), &ephemeral_shared_secret);
    let mut key_bundle_encryption_key = [0u8; 32];
    hk2.expand(b"link_code_pairing_key_bundle_encryption_key", &mut key_bundle_encryption_key)
        .map_err(|_| anyhow!("HKDF expand failed for key bundle encryption key"))?;

    // Construct plaintext key bundle: our identity pub + primary identity pub + adv secret random
    let mut plaintext_key_bundle = Vec::with_capacity(96);
    plaintext_key_bundle.extend_from_slice(identity_key_pub);
    plaintext_key_bundle.extend_from_slice(primary_identity_pub);
    plaintext_key_bundle.extend_from_slice(&adv_secret_random);

    // Encrypt using AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&key_bundle_encryption_key)
        .map_err(|_| anyhow!("Invalid key size for AES-GCM"))?;

    #[allow(deprecated)]
    let nonce = aes_gcm::Nonce::from_slice(&key_bundle_nonce);

    let encrypted_key_bundle = cipher
        .encrypt(nonce, Payload {
            msg: &plaintext_key_bundle,
            aad: &[],
        })
        .map_err(|_| anyhow!("AES-GCM encryption failed"))?;

    // Construct wrapped key bundle: salt + nonce + encrypted bundle
    let mut wrapped_key_bundle = Vec::with_capacity(32 + 12 + encrypted_key_bundle.len());
    wrapped_key_bundle.extend_from_slice(&key_bundle_salt);
    wrapped_key_bundle.extend_from_slice(&key_bundle_nonce);
    wrapped_key_bundle.extend_from_slice(&encrypted_key_bundle);

    // Send companion_finish IQ
    let link_code_companion_reg_finish = NodeBuilder::new("link_code_companion_reg")
        .attrs([
            ("jid", link_cache.jid.to_string()),
            ("stage", "companion_finish".to_string()),
        ])
        .children([
            NodeBuilder::new("link_code_pairing_wrapped_key_bundle")
                .bytes(wrapped_key_bundle)
                .build(),
            NodeBuilder::new("companion_identity_public")
                .bytes(identity_key_pub.to_vec())
                .build(),
            NodeBuilder::new("link_code_pairing_ref")
                .bytes(link_cache.pairing_ref.as_bytes().to_vec())
                .build(),
        ])
        .build();

    client
        .send_iq(crate::request::InfoQuery {
            namespace: "md",
            query_type: crate::request::InfoQueryType::Set,
            to: SERVER_JID.parse()?,
            target: None,
            id: None,
            content: Some(NodeContent::Nodes(vec![link_code_companion_reg_finish])),
            timeout: None,
        })
        .await?;

    info!(target: "Client/PairPhone", "Successfully sent companion_finish");
    Ok(())
}
