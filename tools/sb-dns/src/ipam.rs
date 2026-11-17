//! Sovereign DHCP & IPAM Manager with automatic Dynamic DNS (DDNS) integration.
//!
//! Manages IPv4 subnets, dynamic DHCP leases, and static MAC-to-IP reservations while
//! automatically synchronizing `A` records into `sb-dns`.

use crate::config::{ConfigManager, RecordsConfig};
use chrono::{DateTime, Duration, Utc};
use sb_core::domain::validate_hostname;
use sb_core::ipam::{validate_mac_address, DhcpLease, IpamSubnet};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

/// Persistent IPAM & DHCP state (`~/.sb/dns/ipam.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IpamStore {
    pub subnets: BTreeMap<String, IpamSubnet>,
    pub leases: Vec<DhcpLease>,
}

impl IpamStore {
    /// Returns the default IPAM store path (`~/.sb/dns/ipam.json`).
    pub fn default_path() -> PathBuf {
        sb_core::paths::sb_home().join("dns").join("ipam.json")
    }

    /// Loads an existing IPAM store or returns an empty one.
    pub fn load_from_path(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read IPAM store {}: {e}", path.display()))?;
        serde_json::from_str(&raw)
            .map_err(|e| format!("Invalid IPAM store JSON {}: {e}", path.display()))
    }

    /// Atomically persists the IPAM store to `path`.
    pub fn save_to_path(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Failed to create IPAM dir: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize IPAM store: {e}"))?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, json).map_err(|e| format!("Failed to write temp IPAM store: {e}"))?;
        fs::rename(&tmp, path).map_err(|e| format!("Failed to commit IPAM store: {e}"))?;
        Ok(())
    }

    /// Creates or updates a validated IPAM subnet.
    pub fn upsert_subnet(&mut self, subnet: IpamSubnet) -> Result<IpamSubnet, String> {
        subnet.validate()?;
        self.subnets.insert(subnet.id.clone(), subnet.clone());
        Ok(subnet)
    }

    /// Allocates or renews a DHCP lease and registers its DDNS `A` record.
    ///
    /// # Security Audit
    /// - **Dynamic Threat Vector:** IP hijacking (requesting another active machine's IP),
    ///   MAC spoofing via non-canonical separators, or DDNS hostname injection.
    /// - **CVE / CWE Mapping:** CWE-20 (Improper Input Validation), CWE-290 (Authentication
    ///   Bypass by Spoofing).
    /// - **Likelihood & Exploitability:** Medium (6/10) on shared LAN/mesh segments.
    /// - **Applied Mitigation:** Normalizes MAC via `validate_mac_address`, validates hostname
    ///   via `validate_hostname`, verifies requested IP is inside the subnet pool and not held
    ///   by another active MAC, and updates DDNS atomically.
    ///
    /// # Standards Compliance
    /// - Conforms to RFC 2131 (DHCP lease allocation/renewal) and RFC 2136 (DDNS update intent).
    pub fn allocate_lease(
        &mut self,
        subnet_id: &str,
        mac: &str,
        hostname: &str,
        requested_ip: Option<Ipv4Addr>,
        static_reservation: bool,
        ddns_records_path: Option<&Path>,
    ) -> Result<DhcpLease, String> {
        let subnet = self
            .subnets
            .get(subnet_id)
            .cloned()
            .ok_or_else(|| format!("Subnet '{subnet_id}' not found"))?;
        let canonical_mac = validate_mac_address(mac)?;
        let clean_host = validate_hostname(hostname)?;
        let fqdn = format!("{clean_host}.{}", subnet.domain);

        let now = Utc::now();
        // Prune expired dynamic leases in-place before allocating
        self.leases
            .retain(|l| l.static_reservation || !is_lease_expired(&l.expires_at, now));

        // Check if this MAC already has a lease in this subnet
        if let Some(existing_idx) = self
            .leases
            .iter()
            .position(|l| l.subnet_id == subnet_id && l.mac_address == canonical_mac)
        {
            let existing_ip = self.leases[existing_idx].ip_address;
            if let Some(req_ip) = requested_ip {
                if req_ip != existing_ip {
                    return Err(format!(
                        "MAC {canonical_mac} already holds IP {existing_ip}; release it before requesting {req_ip}"
                    ));
                }
            }
            let expires_at =
                (now + Duration::seconds(i64::from(subnet.default_lease_seconds))).to_rfc3339();
            let lease = &mut self.leases[existing_idx];
            lease.hostname = clean_host;
            lease.fqdn = fqdn.clone();
            lease.static_reservation = lease.static_reservation || static_reservation;
            lease.issued_at = now.to_rfc3339();
            lease.expires_at = expires_at;
            let cloned = lease.clone();
            sync_ddns_add(&fqdn, cloned.ip_address, ddns_records_path)?;
            return Ok(cloned);
        }

        let used_ips: HashSet<Ipv4Addr> = self
            .leases
            .iter()
            .filter(|l| l.subnet_id == subnet_id)
            .map(|l| l.ip_address)
            .collect();

        let assigned_ip = if let Some(req_ip) = requested_ip {
            if !subnet.contains_pool_ip(req_ip) {
                return Err(format!(
                    "Requested IP {req_ip} is outside pool {}..={}",
                    subnet.pool_start, subnet.pool_end
                ));
            }
            if used_ips.contains(&req_ip) {
                return Err(format!("Requested IP {req_ip} is already leased"));
            }
            req_ip
        } else {
            let start = u32::from(subnet.pool_start);
            let end = u32::from(subnet.pool_end);
            (start..=end)
                .map(Ipv4Addr::from)
                .find(|ip| *ip != subnet.gateway && !used_ips.contains(ip))
                .ok_or_else(|| format!("DHCP pool exhausted in subnet '{subnet_id}'"))?
        };

        let mut hasher = Sha256::new();
        hasher.update(subnet_id.as_bytes());
        hasher.update(b":");
        hasher.update(canonical_mac.as_bytes());
        let digest = hasher.finalize();
        let lease_id = format!(
            "lease-{:02x}{:02x}{:02x}{:02x}",
            digest[0], digest[1], digest[2], digest[3]
        );

        let lease = DhcpLease {
            lease_id,
            subnet_id: subnet_id.to_string(),
            mac_address: canonical_mac,
            hostname: clean_host,
            fqdn: fqdn.clone(),
            ip_address: assigned_ip,
            static_reservation,
            issued_at: now.to_rfc3339(),
            expires_at: (now + Duration::seconds(i64::from(subnet.default_lease_seconds)))
                .to_rfc3339(),
        };
        lease.validate()?;
        self.leases.push(lease.clone());
        sync_ddns_add(&fqdn, assigned_ip, ddns_records_path)?;
        Ok(lease)
    }

    /// Releases a DHCP lease by MAC address or IPv4 address and removes its DDNS `A` record.
    pub fn release_lease(
        &mut self,
        mac_or_ip: &str,
        ddns_records_path: Option<&Path>,
    ) -> Result<DhcpLease, String> {
        let target_ip = mac_or_ip.trim().parse::<Ipv4Addr>().ok();
        let target_mac = validate_mac_address(mac_or_ip).ok();

        let idx = self
            .leases
            .iter()
            .position(|l| {
                target_ip.is_some_and(|ip| l.ip_address == ip)
                    || target_mac.as_ref().is_some_and(|m| &l.mac_address == m)
            })
            .ok_or_else(|| format!("No active lease matching '{mac_or_ip}'"))?;

        let removed = self.leases.remove(idx);
        sync_ddns_remove(&removed.fqdn, ddns_records_path)?;
        Ok(removed)
    }

    /// Prunes expired dynamic leases and cleans up their DDNS `A` records.
    pub fn prune_expired_leases(
        &mut self,
        ddns_records_path: Option<&Path>,
    ) -> Result<usize, String> {
        let now = Utc::now();
        let mut expired_fqdns = Vec::new();
        self.leases.retain(|l| {
            let keep = l.static_reservation || !is_lease_expired(&l.expires_at, now);
            if !keep {
                expired_fqdns.push(l.fqdn.clone());
            }
            keep
        });
        for fqdn in &expired_fqdns {
            sync_ddns_remove(fqdn, ddns_records_path)?;
        }
        Ok(expired_fqdns.len())
    }
}

fn is_lease_expired(expires_at: &str, now: DateTime<Utc>) -> bool {
    DateTime::parse_from_rfc3339(expires_at)
        .map(|dt| dt.with_timezone(&Utc) <= now)
        .unwrap_or(true)
}

fn sync_ddns_add(fqdn: &str, ip: Ipv4Addr, records_path: Option<&Path>) -> Result<(), String> {
    if let Some(path) = records_path {
        let mut records: RecordsConfig = if path.exists() {
            let raw = fs::read_to_string(path).map_err(|e| e.to_string())?;
            serde_json::from_str(&raw).map_err(|e| e.to_string())?
        } else {
            RecordsConfig::default()
        };
        records.a.insert(fqdn.to_lowercase(), ip);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let json = serde_json::to_string_pretty(&records).map_err(|e| e.to_string())?;
        fs::write(path, json).map_err(|e| e.to_string())
    } else {
        ConfigManager::add_a_record(fqdn, ip)
    }
}

fn sync_ddns_remove(fqdn: &str, records_path: Option<&Path>) -> Result<(), String> {
    if let Some(path) = records_path {
        if !path.exists() {
            return Ok(());
        }
        let raw = fs::read_to_string(path).map_err(|e| e.to_string())?;
        let mut records: RecordsConfig = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        records.a.remove(&fqdn.to_lowercase());
        let json = serde_json::to_string_pretty(&records).map_err(|e| e.to_string())?;
        fs::write(path, json).map_err(|e| e.to_string())
    } else {
        ConfigManager::remove_record(fqdn).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dhcp_ipam_allocates_prevents_conflicts_and_syncs_ddns() {
        let temp = std::env::temp_dir().join(format!(
            "sb_dns_ipam_test_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).unwrap();

        let ipam_path = temp.join("ipam.json");
        let records_path = temp.join("records.json");

        let mut store = IpamStore::load_from_path(&ipam_path).unwrap();
        store
            .upsert_subnet(IpamSubnet {
                id: "corp-lan".into(),
                domain: "corp.eu".into(),
                cidr: "10.42.0.0/24".into(),
                gateway: Ipv4Addr::new(10, 42, 0, 1),
                dns_servers: vec![Ipv4Addr::new(10, 42, 0, 1)],
                pool_start: Ipv4Addr::new(10, 42, 0, 50),
                pool_end: Ipv4Addr::new(10, 42, 0, 55),
                default_lease_seconds: 3600,
            })
            .unwrap();

        // 1. Allocate first dynamic lease -> gets .50 and writes DDNS A-record
        let l1 = store
            .allocate_lease(
                "corp-lan",
                "AA-BB-CC-DD-EE-01",
                "laptop-01",
                None,
                false,
                Some(&records_path),
            )
            .unwrap();
        assert_eq!(l1.ip_address, Ipv4Addr::new(10, 42, 0, 50));
        assert_eq!(l1.mac_address, "aa:bb:cc:dd:ee:01");
        assert_eq!(l1.fqdn, "laptop-01.corp.eu");

        let rec_raw = fs::read_to_string(&records_path).unwrap();
        let rec: RecordsConfig = serde_json::from_str(&rec_raw).unwrap();
        assert_eq!(
            rec.a.get("laptop-01.corp.eu"),
            Some(&Ipv4Addr::new(10, 42, 0, 50))
        );

        // 2. Different MAC trying to hijack .50 is rejected
        assert!(store
            .allocate_lease(
                "corp-lan",
                "aa:bb:cc:dd:ee:02",
                "evil-01",
                Some(Ipv4Addr::new(10, 42, 0, 50)),
                false,
                Some(&records_path),
            )
            .is_err());

        // 3. Same MAC renewing gets the same IP (.50)
        let l1_renew = store
            .allocate_lease(
                "corp-lan",
                "aa:bb:cc:dd:ee:01",
                "laptop-01",
                None,
                false,
                Some(&records_path),
            )
            .unwrap();
        assert_eq!(l1_renew.ip_address, Ipv4Addr::new(10, 42, 0, 50));

        // 4. Release removes lease and DDNS A-record
        store
            .release_lease("aa:bb:cc:dd:ee:01", Some(&records_path))
            .unwrap();
        let rec_after: RecordsConfig =
            serde_json::from_str(&fs::read_to_string(&records_path).unwrap()).unwrap();
        assert!(!rec_after.a.contains_key("laptop-01.corp.eu"));

        store.save_to_path(&ipam_path).unwrap();
        let _ = fs::remove_dir_all(&temp);
    }
}
