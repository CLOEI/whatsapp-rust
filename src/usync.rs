use crate::client::Client;
use log::debug;
use std::collections::{HashMap, HashSet};
use wacore::types::user::IsOnWhatsAppResponse;
use wacore_binary::jid::{Jid, LEGACY_USER_SERVER, SERVER_JID};
use wacore_binary::node::NodeContent;

impl Client {
    pub(crate) async fn get_user_devices(&self, jids: &[Jid]) -> Result<Vec<Jid>, anyhow::Error> {
        debug!("get_user_devices: Using normal mode for {jids:?}");

        let mut jids_to_fetch: HashSet<Jid> = HashSet::new();
        let mut all_devices = Vec::new();

        // 1. Check the cache first
        for jid in jids.iter().map(|j| j.to_non_ad()) {
            if let Some(cached_devices) = self.get_device_cache().await.get(&jid).await {
                all_devices.extend(cached_devices);
                continue; // Found fresh entry, skip network fetch
            }
            // Not in cache or stale, add to the fetch set (de-duplicated)
            jids_to_fetch.insert(jid);
        }

        // 2. Fetch missing JIDs from the network
        if !jids_to_fetch.is_empty() {
            debug!(
                "get_user_devices: Cache miss, fetching from network for {} unique users",
                jids_to_fetch.len()
            );

            let sid = self.generate_request_id();
            let jids_vec: Vec<Jid> = jids_to_fetch.into_iter().collect();
            let usync_node = wacore::usync::build_get_user_devices_query(&jids_vec, sid.as_str());

            let iq = crate::request::InfoQuery {
                namespace: "usync",
                query_type: crate::request::InfoQueryType::Get,
                to: SERVER_JID.parse().unwrap(),
                content: Some(NodeContent::Nodes(vec![usync_node])),
                id: None,
                target: None,
                timeout: None,
            };
            let resp_node = self.send_iq(iq).await?;
            let fetched_devices = wacore::usync::parse_get_user_devices_response(&resp_node)?;

            // 3. Update the cache with the newly fetched data
            let mut devices_by_user = HashMap::new();
            for device in fetched_devices.iter() {
                let user_jid = device.to_non_ad();
                devices_by_user
                    .entry(user_jid)
                    .or_insert_with(Vec::new)
                    .push(device.clone());
            }

            for (user_jid, devices) in devices_by_user {
                self.get_device_cache()
                    .await
                    .insert(user_jid, devices)
                    .await;
            }
            all_devices.extend(fetched_devices);
        }

        Ok(all_devices)
    }

    /// Checks if the given phone numbers are registered on WhatsApp.
    ///
    /// This function performs a batch query to WhatsApp servers to determine
    /// which phone numbers are registered, and retrieves verified business
    /// name information if available.
    ///
    /// # Arguments
    ///
    /// * `phones` - A slice of phone number strings (e.g., ["1234567890", "9876543210"])
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<IsOnWhatsAppResponse>)` - A vector of responses, one for each registered number
    /// * `Err(anyhow::Error)` - If the query fails or response parsing fails
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example(client: &whatsapp_rust::Client) -> Result<(), Box<dyn std::error::Error>> {
    /// let phones = vec!["1234567890".to_string(), "9876543210".to_string()];
    /// let responses = client.is_on_whatsapp(&phones).await?;
    ///
    /// for response in responses {
    ///     if response.is_in {
    ///         println!("{} is registered on WhatsApp as {}", response.query, response.jid);
    ///         if let Some(verified) = response.verified_name {
    ///             if let Some(name) = verified.details.verified_name {
    ///                 println!("  Verified business name: {}", name);
    ///             }
    ///         }
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn is_on_whatsapp(
        &self,
        phones: &[String],
    ) -> Result<Vec<IsOnWhatsAppResponse>, anyhow::Error> {
        debug!("is_on_whatsapp: Checking {} phone numbers", phones.len());

        // Step 1: Convert phone numbers to JIDs with LEGACY_USER_SERVER
        let jids: Vec<Jid> = phones
            .iter()
            .map(|phone| Jid::new(phone, LEGACY_USER_SERVER))
            .collect();

        // Step 2: Build the usync query
        let sid = self.generate_request_id();
        let usync_node = wacore::usync::build_is_on_whatsapp_query(&jids, sid.as_str());

        // Step 3: Send the IQ query
        let iq = crate::request::InfoQuery {
            namespace: "usync",
            query_type: crate::request::InfoQueryType::Get,
            to: SERVER_JID.parse().unwrap(),
            content: Some(NodeContent::Nodes(vec![usync_node])),
            id: None,
            target: None,
            timeout: None,
        };

        let response_node = self.send_iq(iq).await?;

        // Step 4: Parse the response
        let results = wacore::usync::parse_is_on_whatsapp_response(&response_node)?;

        debug!(
            "is_on_whatsapp: Found {} registered numbers out of {}",
            results.iter().filter(|r| r.is_in).count(),
            phones.len()
        );

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_device_cache_hit() {
        // Create a mock client
        let backend = Arc::new(crate::store::SqliteStore::new(":memory:").await.unwrap())
            as Arc<dyn crate::store::traits::Backend>;
        let pm = Arc::new(
            crate::store::persistence_manager::PersistenceManager::new(backend)
                .await
                .unwrap(),
        );

        let (client, _sync_rx) = crate::client::Client::new(
            pm.clone(),
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        let test_jid: Jid = "1234567890@s.whatsapp.net".parse().unwrap();
        let device_jid: Jid = "1234567890:1@s.whatsapp.net".parse().unwrap();

        // Manually insert into cache
        client
            .get_device_cache()
            .await
            .insert(test_jid.clone(), vec![device_jid.clone()])
            .await;

        // Verify cache hit
        let cached = client.get_device_cache().await.get(&test_jid).await;
        assert!(cached.is_some());
        let cached_devices = cached.unwrap();
        assert_eq!(cached_devices.len(), 1);
        assert_eq!(cached_devices[0], device_jid);
    }

    #[tokio::test]
    async fn test_cache_size_eviction() {
        use moka::future::Cache;

        // Create a small cache
        let cache: Cache<i32, String> = Cache::builder().max_capacity(2).build();

        // Insert 3 items
        cache.insert(1, "one".to_string()).await;
        cache.insert(2, "two".to_string()).await;
        cache.insert(3, "three".to_string()).await;

        // Give time for eviction to occur
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // The cache should have at most 2 items
        let count = cache.entry_count();
        assert!(
            count <= 2,
            "Cache should have at most 2 items, has {}",
            count
        );
    }

    // Mock HTTP client for tests
    #[derive(Debug, Clone)]
    struct MockHttpClient;

    #[async_trait::async_trait]
    impl crate::http::HttpClient for MockHttpClient {
        async fn execute(
            &self,
            _request: crate::http::HttpRequest,
        ) -> Result<crate::http::HttpResponse, anyhow::Error> {
            Err(anyhow::anyhow!("Not implemented"))
        }
    }
}
