use crate::config::{DnsConfig, RecordsConfig};
use crate::directory::{
    AuthorityTrust, DirectoryError, DirectorySnapshot, NodeRecord, RecordState, RevisionCursor,
    ServiceProtocol, ServiceRecord,
};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode, UpdateMessage};
use hickory_proto::rr::rdata::SRV;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::RwLock;

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) const MAX_DNS_MESSAGE_SIZE: usize = 4096;

#[derive(Clone)]
struct CacheEntry {
    message: Message,
    expires_at: Instant,
    stale_until: Instant,
}

#[derive(Default)]
struct DirectoryState {
    authorities: HashMap<String, AuthorityTrust>,
    nodes: HashMap<String, NodeRecord>,
    services: HashMap<String, ServiceRecord>,
    cursors: HashMap<String, RevisionCursor>,
    snapshot_valid_until: HashMap<String, u64>,
}

pub struct DnsResolver {
    pub config: DnsConfig,
    pub records: Arc<Mutex<RecordsConfig>>,
    directory: Arc<RwLock<DirectoryState>>,
    cache: Arc<Mutex<HashMap<String, CacheEntry>>>,
}

impl DnsResolver {
    pub fn new(config: DnsConfig, records: RecordsConfig) -> Self {
        Self {
            config,
            records: Arc::new(Mutex::new(records)),
            directory: Arc::new(RwLock::new(DirectoryState::default())),
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn with_authority(
        config: DnsConfig,
        records: RecordsConfig,
        authority: AuthorityTrust,
    ) -> Self {
        let mesh_id = authority.mesh_id().to_string();
        let mut directory = DirectoryState::default();
        directory.authorities.insert(mesh_id, authority);
        Self {
            config,
            records: Arc::new(Mutex::new(records)),
            directory: Arc::new(RwLock::new(directory)),
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn add_authority(&self, authority: AuthorityTrust) {
        let mut directory = self.directory.write().await;
        directory
            .authorities
            .insert(authority.mesh_id().to_string(), authority);
    }

    /// Verifies the complete signed snapshot before atomically replacing one mesh's directory.
    pub async fn apply_snapshot(
        &self,
        snapshot: DirectorySnapshot,
        now_epoch: u64,
    ) -> Result<(), DirectoryError> {
        // CVE-Threat: Partial directory poisoning or authority rollback.
        // Analysis: Publishing entries before complete validation could expose forged or mixed-mesh answers.
        // Hardening: Validate into temporary maps, check the cursor, then replace the mesh under one write lock.
        let mut directory = self.directory.write().await;
        let authority = directory
            .authorities
            .get(&snapshot.mesh_id)
            .ok_or_else(|| DirectoryError::UnknownAuthority(snapshot.authority_key_id.clone()))?;
        authority.verify_snapshot(&snapshot, now_epoch)?;

        let mut nodes = HashMap::with_capacity(snapshot.nodes.len());
        let mut node_ids = HashMap::with_capacity(snapshot.nodes.len());
        for node in &snapshot.nodes {
            authority.verify_node_record(node, now_epoch)?;
            if node.mesh_id != snapshot.mesh_id
                || node.mesh_name != snapshot.mesh_name
                || node.authority_term > snapshot.authority_term
                || (node.authority_term == snapshot.authority_term
                    && node.revision > snapshot.revision)
                || nodes
                    .insert(node.fqdn.to_ascii_lowercase(), node.clone())
                    .is_some()
                || node_ids.insert(node.node_id.as_str(), node).is_some()
            {
                return Err(DirectoryError::InvalidField(
                    "snapshot node membership or version",
                ));
            }
        }

        let mut services = HashMap::with_capacity(snapshot.services.len());
        for service in &snapshot.services {
            authority.verify_service_record(service, now_epoch)?;
            if service.mesh_id != snapshot.mesh_id
                || service.mesh_name != snapshot.mesh_name
                || service.authority_term > snapshot.authority_term
                || (service.authority_term == snapshot.authority_term
                    && service.revision > snapshot.revision)
                || services
                    .insert(service.service_fqdn.to_ascii_lowercase(), service.clone())
                    .is_some()
            {
                return Err(DirectoryError::InvalidField(
                    "snapshot service membership or version",
                ));
            }
            if service.state == RecordState::Active {
                let node = node_ids
                    .get(service.target_node_id.as_str())
                    .ok_or(DirectoryError::InvalidField("active service target"))?;
                if node.state != RecordState::Active
                    || service.lease_expires_at > node.lease_expires_at
                {
                    return Err(DirectoryError::InvalidField("active service target lease"));
                }
            }
        }

        for fqdn in nodes.keys() {
            if directory
                .nodes
                .get(fqdn)
                .is_some_and(|existing| existing.mesh_id != snapshot.mesh_id)
            {
                return Err(DirectoryError::InvalidField("snapshot node name collision"));
            }
        }
        for fqdn in services.keys() {
            if directory
                .services
                .get(fqdn)
                .is_some_and(|existing| existing.mesh_id != snapshot.mesh_id)
            {
                return Err(DirectoryError::InvalidField(
                    "snapshot service name collision",
                ));
            }
        }

        let digest: [u8; 32] = Sha256::digest(snapshot.signing_bytes()?).into();
        let mut cursor = directory
            .cursors
            .get(&snapshot.mesh_id)
            .copied()
            .unwrap_or_default();
        cursor.observe(snapshot.authority_term, snapshot.revision, digest)?;

        directory
            .nodes
            .retain(|_, record| record.mesh_id != snapshot.mesh_id);
        directory
            .services
            .retain(|_, record| record.mesh_id != snapshot.mesh_id);
        directory.nodes.extend(nodes);
        directory.services.extend(services);
        directory.cursors.insert(snapshot.mesh_id.clone(), cursor);
        directory
            .snapshot_valid_until
            .insert(snapshot.mesh_id, snapshot.valid_until);
        if let Ok(mut cache) = self.cache.lock() {
            cache.clear();
        } else {
            sb_core::logfmt::error(
                "ERR_DNS_CACHE_POISONED",
                "dns.resolver",
                "DNS cache lock poisoned after directory snapshot",
                &[],
            );
        }
        Ok(())
    }

    /// Applies one signed directory mutation after validating it against the
    /// locally enrolled authority key and the mesh's monotonic revision cursor.
    pub async fn apply_node_record(
        &self,
        record: NodeRecord,
        now_epoch: u64,
    ) -> Result<(), DirectoryError> {
        let mut directory = self.directory.write().await;
        let authority = directory
            .authorities
            .get(&record.mesh_id)
            .ok_or_else(|| DirectoryError::UnknownAuthority(record.authority_key_id.clone()))?;
        authority.verify_node_record(&record, now_epoch)?;
        let digest = record_digest(&record)?;
        directory
            .cursors
            .entry(record.mesh_id.clone())
            .or_default()
            .observe(record.authority_term, record.revision, digest)?;

        let name = record.fqdn.to_ascii_lowercase();
        directory.nodes.insert(name.clone(), record);
        self.invalidate_name(&name);
        Ok(())
    }

    /// Applies an approved service mutation. DNS advertises the service only;
    /// callers must still enforce mesh authorization when connecting.
    pub async fn apply_service_record(
        &self,
        record: ServiceRecord,
        now_epoch: u64,
    ) -> Result<(), DirectoryError> {
        let mut directory = self.directory.write().await;
        let authority = directory
            .authorities
            .get(&record.mesh_id)
            .ok_or_else(|| DirectoryError::UnknownAuthority(record.authority_key_id.clone()))?;
        authority.verify_service_record(&record, now_epoch)?;
        let digest = record_digest(&record)?;
        directory
            .cursors
            .entry(record.mesh_id.clone())
            .or_default()
            .observe(record.authority_term, record.revision, digest)?;

        let name = record.service_fqdn.to_ascii_lowercase();
        directory.services.insert(name.clone(), record);
        self.invalidate_name(&name);
        Ok(())
    }

    fn invalidate_name(&self, name: &str) {
        let mut cache = match self.cache.lock() {
            Ok(cache) => cache,
            Err(error) => {
                let e = error.to_string();
                sb_core::logfmt::error(
                    "ERR_DNS_CACHE_POISONED",
                    "dns.resolver",
                    "DNS cache lock poisoned during invalidation",
                    &[("name", name), ("error", &e)],
                );
                return;
            }
        };
        cache.retain(|key, _| !key.starts_with(&format!("{name}:")));
    }

    fn is_private_name(&self, name: &str) -> bool {
        let canonical = name.trim_end_matches('.').to_ascii_lowercase();
        self.config.sovereign_suffixes.iter().any(|suffix| {
            let suffix = suffix.trim_start_matches('.').to_ascii_lowercase();
            canonical == suffix || canonical.ends_with(&format!(".{suffix}"))
        })
    }

    /// Immediately revokes a machine or FQDN from the live directory, static A-records, and DNS cache.
    pub async fn revoke_machine_live(&self, target: &str) {
        let clean = target.trim().trim_end_matches('.').to_ascii_lowercase();
        let mut removed_names = vec![clean.clone()];
        {
            let mut directory = self.directory.write().await;
            let keys_to_remove: Vec<String> = directory
                .nodes
                .iter()
                .filter(|(fqdn, node)| {
                    fqdn.as_str() == clean || node.node_id.eq_ignore_ascii_case(&clean)
                })
                .map(|(fqdn, _)| fqdn.clone())
                .collect();
            for fqdn in keys_to_remove {
                directory.nodes.remove(&fqdn);
                removed_names.push(fqdn);
            }
        }
        if let Ok(mut records) = self.records.lock() {
            for name in &removed_names {
                records.a.remove(name);
                records.aaaa.remove(name);
            }
        }
        for name in &removed_names {
            self.invalidate_name(name);
        }
    }

    pub async fn resolve(&self, query: &Message) -> Result<Message, String> {
        self.resolve_for_client(query, None).await
    }

    /// Resolves a DNS query with optional Split-Horizon awareness for `client_ip`.
    pub async fn resolve_for_client(
        &self,
        query: &Message,
        client_ip: Option<IpAddr>,
    ) -> Result<Message, String> {
        if query.metadata.message_type != MessageType::Query {
            return Ok(self.response(query, ResponseCode::FormErr, false));
        }
        if query.metadata.op_code != OpCode::Query {
            return Ok(self.response(query, ResponseCode::NotImp, false));
        }
        if query.queries.len() != 1 {
            return Ok(self.response(query, ResponseCode::FormErr, false));
        }

        let question = &query.queries[0];
        if question.query_class() != DNSClass::IN {
            return Ok(self.response(query, ResponseCode::Refused, false));
        }

        let qname = question
            .name()
            .to_ascii()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let qtype = question.query_type();
        if self.is_private_name(&qname) {
            let mut resp = self
                .resolve_private(query, question.name(), &qname, qtype)
                .await;
            self.apply_split_horizon(&mut resp, &qname, client_ip);
            return Ok(resp);
        }

        if let Some(mut response) = self.resolve_static(query, question.name(), &qname, qtype) {
            self.apply_split_horizon(&mut response, &qname, client_ip);
            return Ok(response);
        }

        if !self.config.enable_upstream_forwarding
            || (self.config.upstream_servers.is_empty()
                && self.config.doh_upstreams.is_empty()
                && self.config.dot_upstreams.is_empty())
        {
            return Ok(self.response(query, ResponseCode::Refused, false));
        }

        let cache_key = format!("{}:{:?}:{:?}", qname, qtype, question.query_class());
        if let Some(cached) = self.cached_response(&cache_key, query.id()) {
            return Ok(cached);
        }

        let mut last_error: Option<String> = None;
        for doh_url in &self.config.doh_upstreams {
            match crate::encrypted_upstream::forward_query_doh(doh_url, query).await {
                Ok(mut response) => {
                    self.cache_response(cache_key.clone(), &response);
                    response.metadata.id = query.id();
                    return Ok(response);
                }
                Err(error) => last_error = Some(error),
            }
        }
        for dot in &self.config.dot_upstreams {
            match crate::encrypted_upstream::forward_query_dot(dot.addr, &dot.server_name, query)
                .await
            {
                Ok(mut response) => {
                    self.cache_response(cache_key.clone(), &response);
                    response.metadata.id = query.id();
                    return Ok(response);
                }
                Err(error) => last_error = Some(error),
            }
        }
        for upstream in &self.config.upstream_servers {
            match forward_query(*upstream, query).await {
                Ok(mut response) => {
                    self.cache_response(cache_key.clone(), &response);
                    response.metadata.id = query.id();
                    return Ok(response);
                }
                Err(error) => last_error = Some(error.to_string()),
            }
        }

        if let Some(stale) = self.stale_response(&cache_key, query.id()) {
            sb_core::logfmt::warn(
                "WARN_DNS_SERVE_STALE",
                "dns.resolver",
                "Serving stale cached DNS response after upstream failure",
                &[("qname", &qname)],
            );
            return Ok(stale);
        }

        if let Some(error) = last_error {
            sb_core::logfmt::warn(
                "ERR_DNS_UPSTREAM",
                "dns.resolver",
                "DNS upstream resolution failed",
                &[("qname", &qname), ("error", &error)],
            );
        }
        Ok(self.response(query, ResponseCode::ServFail, false))
    }

    fn apply_split_horizon(&self, response: &mut Message, qname: &str, client_ip: Option<IpAddr>) {
        let Some(public_ip) = self.config.split_horizon_public_ip else {
            return;
        };
        let Some(client) = client_ip else {
            return;
        };
        if is_internal_client_ip(client) || qname.ends_with(".sbm") || qname.ends_with(".mesh") {
            return;
        }
        for ans in response.answers.iter_mut() {
            if let RData::A(v4) = &ans.data {
                if is_internal_client_ip(IpAddr::V4(v4.0)) {
                    ans.data = RData::A(public_ip.into());
                }
            }
        }
    }

    fn response(&self, query: &Message, code: ResponseCode, authoritative: bool) -> Message {
        let mut response = Message::new(query.id(), MessageType::Response, query.metadata.op_code);
        response.metadata.recursion_desired = query.metadata.recursion_desired;
        response.metadata.recursion_available = self.config.enable_upstream_forwarding;
        response.metadata.authoritative = authoritative;
        response.metadata.response_code = code;
        for question in &query.queries {
            response.add_query(question.clone());
        }
        response
    }

    async fn resolve_private(
        &self,
        query: &Message,
        owner: &Name,
        qname: &str,
        qtype: RecordType,
    ) -> Message {
        let now_epoch = chrono::Utc::now().timestamp().max(0) as u64;
        let directory = self.directory.read().await;
        let mut response = self.response(query, ResponseCode::NoError, true);

        let service = if qtype == RecordType::SRV {
            directory
                .services
                .values()
                .find(|service| service_srv_owner(service).as_deref() == Some(qname))
        } else {
            directory.services.get(qname)
        };
        if let Some(service) = service {
            let snapshot_expiry = directory
                .snapshot_valid_until
                .get(&service.mesh_id)
                .copied()
                .unwrap_or(u64::MAX);
            if service.state != RecordState::Active
                || service.lease_expires_at <= now_epoch
                || snapshot_expiry <= now_epoch
            {
                return self.response(query, ResponseCode::NXDomain, true);
            }
            let Some(node) = directory.nodes.values().find(|node| {
                node.node_id == service.target_node_id
                    && node.mesh_id == service.mesh_id
                    && node.state == RecordState::Active
                    && node.lease_expires_at > now_epoch
            }) else {
                return self.response(query, ResponseCode::NXDomain, true);
            };
            let ttl = self.record_ttl(
                service
                    .lease_expires_at
                    .min(node.lease_expires_at)
                    .min(snapshot_expiry),
                now_epoch,
            );
            match qtype {
                RecordType::A => {
                    for address in &node.overlay_addresses {
                        if let IpAddr::V4(address) = address {
                            response.add_answer(Record::from_rdata(
                                owner.clone(),
                                ttl,
                                RData::A((*address).into()),
                            ));
                        }
                    }
                }
                RecordType::AAAA => {
                    for address in &node.overlay_addresses {
                        if let IpAddr::V6(address) = address {
                            response.add_answer(Record::from_rdata(
                                owner.clone(),
                                ttl,
                                RData::AAAA((*address).into()),
                            ));
                        }
                    }
                }
                RecordType::SRV => {
                    if let Ok(target) = Name::from_ascii(&node.fqdn) {
                        response.add_answer(Record::from_rdata(
                            owner.clone(),
                            ttl,
                            RData::SRV(SRV::new(0, 0, service.service_port, target)),
                        ));
                    }
                }
                _ => {}
            }
            return response;
        }

        if qtype == RecordType::SRV && directory.services.contains_key(qname) {
            return response;
        }

        if let Some(node) = directory.nodes.get(qname) {
            let snapshot_expiry = directory
                .snapshot_valid_until
                .get(&node.mesh_id)
                .copied()
                .unwrap_or(u64::MAX);
            if node.state != RecordState::Active
                || node.lease_expires_at <= now_epoch
                || snapshot_expiry <= now_epoch
            {
                return self.response(query, ResponseCode::NXDomain, true);
            }
            let ttl = self.record_ttl(node.lease_expires_at.min(snapshot_expiry), now_epoch);
            match qtype {
                RecordType::A => {
                    for address in &node.overlay_addresses {
                        if let IpAddr::V4(address) = address {
                            response.add_answer(Record::from_rdata(
                                owner.clone(),
                                ttl,
                                RData::A((*address).into()),
                            ));
                        }
                    }
                }
                RecordType::AAAA => {
                    for address in &node.overlay_addresses {
                        if let IpAddr::V6(address) = address {
                            response.add_answer(Record::from_rdata(
                                owner.clone(),
                                ttl,
                                RData::AAAA((*address).into()),
                            ));
                        }
                    }
                }
                _ => {}
            }
            return response;
        }

        if let Some(static_resp) = self.resolve_static(query, owner, qname, qtype) {
            return static_resp;
        }

        self.response(query, ResponseCode::NXDomain, true)
    }

    fn record_ttl(&self, lease_expires_at: u64, now_epoch: u64) -> u32 {
        self.config.default_ttl.min(
            lease_expires_at
                .saturating_sub(now_epoch)
                .min(u32::MAX as u64) as u32,
        )
    }

    fn resolve_static(
        &self,
        query: &Message,
        owner: &Name,
        qname: &str,
        qtype: RecordType,
    ) -> Option<Message> {
        let records = match self.records.lock() {
            Ok(records) => records,
            Err(error) => {
                let e = error.to_string();
                sb_core::logfmt::error(
                    "ERR_DNS_STATIC_POISONED",
                    "dns.resolver",
                    "DNS static-record lock poisoned",
                    &[("error", &e)],
                );
                return Some(self.response(query, ResponseCode::ServFail, false));
            }
        };
        let ttl = self.config.default_ttl;
        let mut response = self.response(query, ResponseCode::NoError, true);

        match qtype {
            RecordType::A => {
                if let Some(ip) = records.a.get(qname) {
                    response.add_answer(Record::from_rdata(
                        owner.clone(),
                        ttl,
                        RData::A((*ip).into()),
                    ));
                    return Some(response);
                }
                if let Some(ip) = lookup_wildcard(&records.wildcards, qname) {
                    response.add_answer(Record::from_rdata(
                        owner.clone(),
                        ttl,
                        RData::A(ip.into()),
                    ));
                    return Some(response);
                }
            }
            RecordType::AAAA => {
                if let Some(ip) = records.aaaa.get(qname) {
                    response.add_answer(Record::from_rdata(
                        owner.clone(),
                        ttl,
                        RData::AAAA((*ip).into()),
                    ));
                    return Some(response);
                }
            }
            RecordType::CNAME => {
                if let Some(target) = records.cname.get(qname) {
                    if let Ok(target) = Name::from_ascii(target) {
                        response.add_answer(Record::from_rdata(
                            owner.clone(),
                            ttl,
                            RData::CNAME(hickory_proto::rr::rdata::CNAME(target)),
                        ));
                        return Some(response);
                    }
                }
            }
            RecordType::TXT => {
                if let Some(text) = records.txt.get(qname) {
                    if text.len() <= 255 {
                        response.add_answer(Record::from_rdata(
                            owner.clone(),
                            ttl,
                            RData::TXT(hickory_proto::rr::rdata::TXT::new(vec![text.clone()])),
                        ));
                        return Some(response);
                    }
                }
            }
            RecordType::SRV => {
                if let Some(entries) = records.srv.get(qname) {
                    let mut added = false;
                    for entry in entries {
                        if let Ok(mut target) = Name::from_ascii(&entry.target) {
                            target.set_fqdn(true);
                            response.add_answer(Record::from_rdata(
                                owner.clone(),
                                ttl,
                                RData::SRV(hickory_proto::rr::rdata::SRV::new(
                                    entry.priority,
                                    entry.weight,
                                    entry.port,
                                    target,
                                )),
                            ));
                            added = true;
                        }
                    }
                    if added {
                        return Some(response);
                    }
                }
            }
            _ => {}
        }
        None
    }

    fn cached_response(&self, key: &str, id: u16) -> Option<Message> {
        let mut cache = match self.cache.lock() {
            Ok(cache) => cache,
            Err(error) => {
                let e = error.to_string();
                sb_core::logfmt::error(
                    "ERR_DNS_CACHE_POISONED",
                    "dns.resolver",
                    "DNS cache lock poisoned during lookup",
                    &[("error", &e)],
                );
                return None;
            }
        };
        let now = Instant::now();
        match cache.get(key) {
            Some(entry) if now < entry.expires_at => {
                let mut message = entry.message.clone();
                message.metadata.id = id;
                let remaining_ttl = entry
                    .expires_at
                    .duration_since(now)
                    .as_secs()
                    .min(u32::MAX as u64) as u32;
                for record in message.answers.iter_mut() {
                    record.ttl = record.ttl.min(remaining_ttl);
                }
                for record in message.authorities.iter_mut() {
                    record.ttl = record.ttl.min(remaining_ttl);
                }
                for record in message.additionals.iter_mut() {
                    record.ttl = record.ttl.min(remaining_ttl);
                }
                Some(message)
            }
            Some(entry) if now < entry.stale_until => None,
            Some(_) => {
                cache.remove(key);
                None
            }
            None => None,
        }
    }

    fn stale_response(&self, key: &str, id: u16) -> Option<Message> {
        let cache = self.cache.lock().ok()?;
        let now = Instant::now();
        let entry = cache.get(key)?;
        if now >= entry.stale_until {
            return None;
        }
        let mut message = entry.message.clone();
        message.metadata.id = id;
        for record in message.answers.iter_mut() {
            record.ttl = 1;
        }
        Some(message)
    }

    fn cache_response(&self, key: String, message: &Message) {
        if self.config.cache_size == 0 {
            return;
        }
        let ttl = if message.answers.is_empty() {
            if matches!(
                message.metadata.response_code,
                ResponseCode::NXDomain | ResponseCode::NoError
            ) {
                self.config.negative_cache_ttl_secs
            } else {
                0
            }
        } else {
            message.answers.iter().map(|r| r.ttl).min().unwrap_or(0)
        };
        if ttl == 0 {
            return;
        }
        let mut cache = match self.cache.lock() {
            Ok(cache) => cache,
            Err(error) => {
                let e = error.to_string();
                sb_core::logfmt::error(
                    "ERR_DNS_CACHE_POISONED",
                    "dns.resolver",
                    "DNS cache lock poisoned while storing response",
                    &[("error", &e)],
                );
                return;
            }
        };
        let now = Instant::now();
        cache.retain(|_, entry| now < entry.stale_until);
        let max_entries = self.config.cache_size.min(65_536);
        if cache.len() >= max_entries {
            if let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(key, _)| key.clone())
            {
                cache.remove(&oldest_key);
            }
        }
        let mut cached = message.clone();
        cached.metadata.id = 0;
        let expires_at = now + Duration::from_secs(ttl as u64);
        let stale_until = expires_at + Duration::from_secs(self.config.serve_stale_secs);
        cache.insert(
            key,
            CacheEntry {
                message: cached,
                expires_at,
                stale_until,
            },
        );
    }
}

fn is_internal_client_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || (v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1]))
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local(),
    }
}

fn lookup_wildcard(wildcards: &HashMap<String, std::net::Ipv4Addr>, qname: &str) -> Option<std::net::Ipv4Addr> {
    let mut best: Option<(usize, std::net::Ipv4Addr)> = None;
    for (pattern, ip) in wildcards {
        let p = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
        if let Some(suffix) = p.strip_prefix("*.") {
            if qname.ends_with(&format!(".{suffix}")) && qname.len() > suffix.len() + 1 {
                let len = suffix.len();
                if best.map(|(b_len, _)| len > b_len).unwrap_or(true) {
                    best = Some((len, *ip));
                }
            }
        }
    }
    best.map(|(_, ip)| ip)
}

fn record_digest<T: serde::Serialize>(record: &T) -> Result<[u8; 32], DirectoryError> {
    let bytes =
        serde_json::to_vec(record).map_err(|_| DirectoryError::InvalidField("record encoding"))?;
    Ok(Sha256::digest(bytes).into())
}

fn service_srv_owner(service: &ServiceRecord) -> Option<String> {
    let (service_label, mesh_domain) = service.service_fqdn.split_once('.')?;
    let protocol = match service.service_protocol {
        ServiceProtocol::Tcp => "_tcp",
        ServiceProtocol::Udp => "_udp",
    };
    Some(format!("_{service_label}.{protocol}.{mesh_domain}"))
}

async fn forward_query(upstream: SocketAddr, query: &Message) -> Result<Message, String> {
    let mut forwarded = query.clone();
    let request_id = rand::random::<u16>();
    forwarded.metadata.id = request_id;
    let request_bytes = forwarded
        .to_vec()
        .map_err(|error| format!("DNS query encoding failed: {error}"))?;
    if request_bytes.len() > MAX_DNS_MESSAGE_SIZE {
        return Err("DNS query exceeds the configured size limit".to_string());
    }

    let bind_addr = if upstream.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|error| format!("DNS upstream socket bind failed: {error}"))?;
    socket
        .send_to(&request_bytes, upstream)
        .await
        .map_err(|error| format!("DNS upstream send failed: {error}"))?;

    let mut response_bytes = vec![0u8; MAX_DNS_MESSAGE_SIZE + 1];
    let (length, source) =
        tokio::time::timeout(UPSTREAM_TIMEOUT, socket.recv_from(&mut response_bytes))
            .await
            .map_err(|_| "DNS upstream UDP request timed out".to_string())?
            .map_err(|error| format!("DNS upstream receive failed: {error}"))?;
    if source != upstream || length > MAX_DNS_MESSAGE_SIZE {
        return Err("DNS upstream response source or size is invalid".to_string());
    }
    response_bytes.truncate(length);
    let mut response = Message::from_vec(&response_bytes)
        .map_err(|error| format!("DNS upstream response is malformed: {error}"))?;
    validate_upstream_response(&forwarded, &response, request_id)?;
    if response.metadata.truncation {
        response = forward_query_tcp(upstream, &request_bytes, request_id, &forwarded).await?;
    }
    Ok(response)
}

async fn forward_query_tcp(
    upstream: SocketAddr,
    request_bytes: &[u8],
    request_id: u16,
    query: &Message,
) -> Result<Message, String> {
    let response = tokio::time::timeout(UPSTREAM_TIMEOUT, async {
        let mut stream = TcpStream::connect(upstream).await?;
        let length = u16::try_from(request_bytes.len()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "DNS query too large")
        })?;
        tokio::io::AsyncWriteExt::write_all(&mut stream, &length.to_be_bytes()).await?;
        tokio::io::AsyncWriteExt::write_all(&mut stream, request_bytes).await?;
        let mut prefix = [0u8; 2];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut prefix).await?;
        let response_len = u16::from_be_bytes(prefix) as usize;
        if response_len > MAX_DNS_MESSAGE_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "DNS response too large",
            ));
        }
        let mut response_bytes = vec![0u8; response_len];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut response_bytes).await?;
        Ok::<_, std::io::Error>(response_bytes)
    })
    .await
    .map_err(|_| "DNS upstream TCP request timed out".to_string())?
    .map_err(|error| format!("DNS upstream TCP request failed: {error}"))?;
    let response = Message::from_vec(&response)
        .map_err(|error| format!("DNS upstream TCP response is malformed: {error}"))?;
    validate_upstream_response(query, &response, request_id)?;
    Ok(response)
}

fn validate_upstream_response(
    query: &Message,
    response: &Message,
    expected_id: u16,
) -> Result<(), String> {
    crate::protocol::validate_dns_response(
        query,
        response,
        expected_id,
        "DNS upstream response does not match the outstanding query",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::{DirectorySnapshot, NodeRecord, ServiceRecord};
    use ed25519_dalek::SigningKey;
    use hickory_proto::op::Query;
    use hickory_proto::rr::rdata::A;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tokio::net::UdpSocket;

    fn query(name: &str, query_type: RecordType) -> Message {
        let name = Name::from_ascii(name).unwrap();
        let query = Query::query(name, query_type);
        let mut message = Message::new(100, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.add_query(query);
        message
    }

    fn signed_resolver() -> (DnsResolver, SigningKey) {
        let key = SigningKey::from_bytes(&[17; 32]);
        let authority = AuthorityTrust::new(
            "mesh-dev-01",
            HashMap::from([("auth-1".to_string(), key.verifying_key().to_bytes())]),
        )
        .unwrap();
        (
            DnsResolver::with_authority(DnsConfig::default(), RecordsConfig::default(), authority),
            key,
        )
    }

    fn node_record(key: &SigningKey) -> NodeRecord {
        node_record_at(key, 1, Ipv4Addr::new(10, 42, 0, 1))
    }

    fn node_record_at(key: &SigningKey, revision: u64, address: Ipv4Addr) -> NodeRecord {
        NodeRecord::sign(
            "mesh-dev-01",
            "dev",
            "anchor-01.dev.sbm",
            "node-1",
            "identity-1",
            vec![IpAddr::V4(address), IpAddr::V6(Ipv6Addr::LOCALHOST)],
            "owner-1",
            RecordState::Active,
            revision,
            2_000_000_000,
            1,
            "auth-1",
            key,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn resolves_only_verified_mesh_directory_records() {
        let (resolver, key) = signed_resolver();
        let record = node_record(&key);
        resolver
            .apply_node_record(record, 1_900_000_000)
            .await
            .unwrap();

        let response = resolver
            .resolve(&query("anchor-01.dev.sbm", RecordType::A))
            .await
            .unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.metadata.authoritative);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(
            response.answers[0].data,
            RData::A(A::from(Ipv4Addr::new(10, 42, 0, 1)))
        );
        assert!(response.answers[0].ttl <= 300);
    }

    #[tokio::test]
    async fn snapshot_is_verified_atomically_and_bounds_answer_ttl() {
        let (mut resolver, key) = signed_resolver();
        resolver.config.default_ttl = 60;
        let now_epoch = chrono::Utc::now().timestamp().max(0) as u64;
        let snapshot_expiry = now_epoch + 50;
        let valid_snapshot = DirectorySnapshot::sign(
            "mesh-dev-01",
            "dev",
            1,
            1,
            snapshot_expiry,
            "auth-1",
            vec![node_record(&key)],
            vec![],
            &key,
        )
        .unwrap();
        let valid_snapshot: DirectorySnapshot =
            serde_json::from_slice(&serde_json::to_vec(&valid_snapshot).unwrap()).unwrap();
        resolver
            .apply_snapshot(valid_snapshot, now_epoch)
            .await
            .unwrap();

        let response = resolver
            .resolve(&query("anchor-01.dev.sbm", RecordType::A))
            .await
            .unwrap();
        assert_eq!(response.answers.len(), 1);
        assert!(response.answers[0].ttl <= 50);

        let mut forged_node = node_record_at(&key, 2, Ipv4Addr::new(10, 42, 0, 2));
        forged_node.owner_id = "tampered-after-signing".to_string();
        let invalid_snapshot = DirectorySnapshot::sign(
            "mesh-dev-01",
            "dev",
            1,
            2,
            snapshot_expiry + 100,
            "auth-1",
            vec![forged_node],
            vec![],
            &key,
        )
        .unwrap();
        assert!(resolver
            .apply_snapshot(invalid_snapshot, now_epoch)
            .await
            .is_err());

        let unchanged = resolver
            .resolve(&query("anchor-01.dev.sbm", RecordType::A))
            .await
            .unwrap();
        assert_eq!(
            unchanged.answers[0].data,
            RData::A(A::from(Ipv4Addr::new(10, 42, 0, 1)))
        );

        let valid_update = DirectorySnapshot::sign(
            "mesh-dev-01",
            "dev",
            1,
            2,
            snapshot_expiry + 100,
            "auth-1",
            vec![node_record_at(&key, 2, Ipv4Addr::new(10, 42, 0, 2))],
            vec![],
            &key,
        )
        .unwrap();
        resolver
            .apply_snapshot(valid_update, now_epoch)
            .await
            .unwrap();
        let updated = resolver
            .resolve(&query("anchor-01.dev.sbm", RecordType::A))
            .await
            .unwrap();
        assert_eq!(
            updated.answers[0].data,
            RData::A(A::from(Ipv4Addr::new(10, 42, 0, 2)))
        );
    }

    #[tokio::test]
    async fn private_mesh_queries_never_forward_to_public_upstreams() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let receive = tokio::spawn(async move {
            let mut packet = [0u8; 512];
            tokio::time::timeout(Duration::from_millis(150), upstream.recv_from(&mut packet))
                .await
                .is_ok()
        });

        let mut config = DnsConfig::default();
        config.upstream_servers = vec![upstream_addr];
        let resolver = DnsResolver::new(config, RecordsConfig::default());
        let response = resolver
            .resolve(&query("missing.dev.sbm", RecordType::A))
            .await
            .unwrap();

        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        assert!(response.metadata.authoritative);
        assert!(!receive.await.unwrap());
    }

    #[tokio::test]
    async fn forwards_public_queries_and_caches_only_valid_matching_responses() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let mut bytes = [0u8; 2048];
            let (length, peer) = upstream.recv_from(&mut bytes).await.unwrap();
            let request = Message::from_vec(&bytes[..length]).unwrap();
            let mut answer = request.clone();
            answer.metadata.message_type = MessageType::Response;
            answer.add_answer(Record::from_rdata(
                Name::from_ascii("example.com").unwrap(),
                25,
                RData::A(A::from(Ipv4Addr::new(203, 0, 113, 7))),
            ));
            upstream
                .send_to(&answer.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });

        let mut config = DnsConfig::default();
        config.upstream_servers = vec![upstream_addr];
        let resolver = DnsResolver::new(config, RecordsConfig::default());
        let first = resolver
            .resolve(&query("example.com", RecordType::A))
            .await
            .unwrap();
        responder.await.unwrap();
        assert_eq!(first.answers.len(), 1);
        assert_eq!(first.metadata.id, 100);

        let second_query = {
            let mut q = query("example.com", RecordType::A);
            q.metadata.id = 101;
            q
        };
        let second = resolver.resolve(&second_query).await.unwrap();
        assert_eq!(second.metadata.id, 101);
        assert_eq!(second.answers.len(), 1);
    }

    #[tokio::test]
    async fn directory_service_resolves_to_its_active_node() {
        let (resolver, key) = signed_resolver();
        resolver
            .apply_node_record(node_record(&key), 1_900_000_000)
            .await
            .unwrap();
        let service = ServiceRecord::sign(
            "mesh-dev-01",
            "dev",
            "api.dev.sbm",
            "node-1",
            ServiceProtocol::Tcp,
            8443,
            "owner-1",
            RecordState::Active,
            2,
            1_999_999_999,
            1,
            "auth-1",
            &key,
        )
        .unwrap();
        resolver
            .apply_service_record(service, 1_900_000_000)
            .await
            .unwrap();

        let srv = resolver
            .resolve(&query("_api._tcp.dev.sbm", RecordType::SRV))
            .await
            .unwrap();
        assert_eq!(srv.answers.len(), 1);
        assert_eq!(srv.answers[0].record_type(), RecordType::SRV);
        assert_eq!(srv.answers[0].name.to_ascii(), "_api._tcp.dev.sbm");
        assert!(srv.answers[0].ttl <= 300);
        assert_eq!(
            resolver
                .resolve(&query("api.dev.sbm", RecordType::SRV))
                .await
                .unwrap()
                .metadata
                .response_code,
            ResponseCode::NoError
        );
    }

    #[tokio::test]
    async fn rejects_multi_question_and_non_in_queries() {
        let resolver = DnsResolver::new(DnsConfig::default(), RecordsConfig::default());
        let mut multiple = query("example.com", RecordType::A);
        multiple.add_query(query("example.net", RecordType::A).queries[0].clone());
        assert_eq!(
            resolver
                .resolve(&multiple)
                .await
                .unwrap()
                .metadata
                .response_code,
            ResponseCode::FormErr
        );

        let mut chaos = query("example.com", RecordType::A);
        chaos.queries[0].set_query_class(DNSClass::CH);
        assert_eq!(
            resolver
                .resolve(&chaos)
                .await
                .unwrap()
                .metadata
                .response_code,
            ResponseCode::Refused
        );
    }

    #[tokio::test]
    async fn resolves_static_srv_records_for_dc_discovery() {
        let mut records = RecordsConfig::default();
        records.srv.insert(
            "_dc._tcp.corp.sbm".to_string(),
            vec![crate::config::SrvRecordConfig {
                priority: 10,
                weight: 0,
                port: 8443,
                target: "dc.corp.sbm".to_string(),
            }],
        );
        let resolver = DnsResolver::new(DnsConfig::default(), records);
        let res = resolver
            .resolve(&query("_dc._tcp.corp.sbm", RecordType::SRV))
            .await
            .unwrap();
        assert_eq!(res.answers.len(), 1);
        assert_eq!(res.answers[0].record_type(), RecordType::SRV);
    }

    #[tokio::test]
    async fn wildcard_and_split_horizon_and_negative_cache_work() {
        let mut records = RecordsConfig::default();
        records
            .wildcards
            .insert("*.apps.corp.eu".into(), Ipv4Addr::new(10, 42, 0, 1));
        let mut cfg = DnsConfig::default();
        cfg.split_horizon_public_ip = Some(Ipv4Addr::new(203, 0, 113, 10));
        cfg.negative_cache_ttl_secs = 45;
        let resolver = DnsResolver::new(cfg, records);

        // Internal client gets mesh IP via wildcard
        let internal_res = resolver
            .resolve_for_client(
                &query("grafana.apps.corp.eu", RecordType::A),
                Some(IpAddr::V4(Ipv4Addr::new(10, 42, 0, 15))),
            )
            .await
            .unwrap();
        assert_eq!(internal_res.answers.len(), 1);
        assert_eq!(
            internal_res.answers[0].data,
            RData::A(Ipv4Addr::new(10, 42, 0, 1).into())
        );

        // External client gets public IP via Split-Horizon
        let external_res = resolver
            .resolve_for_client(
                &query("grafana.apps.corp.eu", RecordType::A),
                Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42))),
            )
            .await
            .unwrap();
        assert_eq!(
            external_res.answers[0].data,
            RData::A(Ipv4Addr::new(203, 0, 113, 10).into())
        );

        // Negative caching stores NXDOMAIN
        let nx = resolver.response(&query("missing.example.org", RecordType::A), ResponseCode::NXDomain, false);
        resolver.cache_response("missing.example.org:A:IN".into(), &nx);
        let cached_nx = resolver.cached_response("missing.example.org:A:IN", 99).unwrap();
        assert_eq!(cached_nx.metadata.response_code, ResponseCode::NXDomain);
    }
}
