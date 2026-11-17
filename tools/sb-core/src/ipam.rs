//! IP Address Management (IPAM) and DHCP lease models with strict validation.
//!
//! Designed for sovereign LAN/Mesh DHCP allocation and automatic Dynamic DNS (DDNS)
//! registration in `sb-dns`. Conforms to RFC 2131 (DHCP), RFC 4632 (CIDR), and IEEE 802 (MAC).

use crate::domain::{validate_domain_name, validate_hostname};
use crate::policy::validate_policy_id;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Minimum and maximum allowed DHCP lease durations (1 minute to 7 days).
pub const MIN_LEASE_SECONDS: u32 = 60;
pub const MAX_LEASE_SECONDS: u32 = 7 * 24 * 3600;

/// Normalizes and validates an IEEE 802 MAC-48 address (`aa:bb:cc:dd:ee:ff`).
///
/// # Security Audit
/// - **Dynamic Threat Vector:** Malformed or spoofed MAC strings causing parser confusion or
///   duplicate lease bypasses via case/separator variations (`AA-BB-...` vs `aa:bb:...`).
/// - **CVE / CWE Mapping:** CWE-20 (Improper Input Validation), CWE-1289 (Improper Validation
///   of Unsafe Equivalence in Input).
/// - **Likelihood & Exploitability:** Medium (5/10) on DHCP/IPAM APIs.
/// - **Applied Mitigation:** Parses 6 hex octets (accepting `:` or `-` separators), rejects
///   broadcast (`ff:ff:ff:ff:ff:ff`) and all-zero (`00:00:00:00:00:00`) addresses, and returns
///   a single canonical lowercase colon-separated representation.
///
/// # Standards Compliance
/// - Conforms to IEEE 802-2014 §8.1 (48-bit MAC addressing).
pub fn validate_mac_address(mac: &str) -> Result<String, String> {
    let trimmed = mac.trim();
    let sep = if trimmed.contains(':') {
        ':'
    } else if trimmed.contains('-') {
        '-'
    } else {
        return Err(format!(
            "Invalid MAC address '{mac}' (expected 6 hex octets)"
        ));
    };
    let parts: Vec<&str> = trimmed.split(sep).collect();
    if parts.len() != 6 {
        return Err(format!("Invalid MAC address '{mac}' (expected 6 octets)"));
    }
    let mut octets = [0u8; 6];
    for (idx, part) in parts.iter().enumerate() {
        if part.len() != 2 || !part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("Invalid MAC octet '{part}' in '{mac}'"));
        }
        octets[idx] = u8::from_str_radix(part, 16)
            .map_err(|_| format!("Invalid hex octet '{part}' in '{mac}'"))?;
    }
    if octets == [0, 0, 0, 0, 0, 0] || octets == [0xff, 0xff, 0xff, 0xff, 0xff, 0xff] {
        return Err(format!("Reserved MAC address '{mac}' is not allowed"));
    }
    Ok(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        octets[0], octets[1], octets[2], octets[3], octets[4], octets[5]
    ))
}

/// Parses an IPv4 CIDR string (e.g. `10.42.0.0/24`) into `(network_u32, mask_u32)`.
///
/// # Standards Compliance
/// - Conforms to RFC 4632 (Classless Inter-domain Routing).
pub fn parse_ipv4_cidr(cidr: &str) -> Result<(u32, u32), String> {
    let (ip_str, prefix_str) = cidr
        .trim()
        .split_once('/')
        .ok_or_else(|| format!("Invalid CIDR '{cidr}' (expected A.B.C.D/P)"))?;
    let ip: Ipv4Addr = ip_str
        .parse()
        .map_err(|_| format!("Invalid IPv4 address in CIDR '{cidr}'"))?;
    let prefix: u32 = prefix_str
        .parse()
        .map_err(|_| format!("Invalid prefix length in CIDR '{cidr}'"))?;
    if !(8..=30).contains(&prefix) {
        return Err(format!("CIDR prefix /{prefix} must be within /8..=/30"));
    }
    let mask = !0u32 << (32 - prefix);
    let network = u32::from(ip) & mask;
    Ok((network, mask))
}

/// IPAM Subnet & DHCP Pool definition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpamSubnet {
    pub id: String,
    pub domain: String,
    pub cidr: String,
    pub gateway: Ipv4Addr,
    pub dns_servers: Vec<Ipv4Addr>,
    pub pool_start: Ipv4Addr,
    pub pool_end: Ipv4Addr,
    pub default_lease_seconds: u32,
}

impl IpamSubnet {
    /// Validates subnet ID, domain, CIDR containment of gateway/pool, and lease TTL bounds.
    pub fn validate(&self) -> Result<(), String> {
        validate_policy_id(&self.id)?;
        validate_domain_name(&self.domain)?;
        let (network, mask) = parse_ipv4_cidr(&self.cidr)?;
        let start_u32 = u32::from(self.pool_start);
        let end_u32 = u32::from(self.pool_end);
        let gw_u32 = u32::from(self.gateway);

        if (gw_u32 & mask) != network {
            return Err(format!(
                "Gateway {} is outside CIDR {}",
                self.gateway, self.cidr
            ));
        }
        if (start_u32 & mask) != network || (end_u32 & mask) != network {
            return Err(format!(
                "DHCP pool {}..={} must be inside CIDR {}",
                self.pool_start, self.pool_end, self.cidr
            ));
        }
        if start_u32 > end_u32 {
            return Err("pool_start must be <= pool_end".into());
        }
        if !(MIN_LEASE_SECONDS..=MAX_LEASE_SECONDS).contains(&self.default_lease_seconds) {
            return Err(format!(
                "default_lease_seconds must be within {MIN_LEASE_SECONDS}..={MAX_LEASE_SECONDS}"
            ));
        }
        Ok(())
    }

    /// Validates that a host IP falls inside the configured DHCP pool and is not the gateway.
    pub fn contains_pool_ip(&self, ip: Ipv4Addr) -> bool {
        let u = u32::from(ip);
        u >= u32::from(self.pool_start) && u <= u32::from(self.pool_end) && ip != self.gateway
    }
}

/// Active DHCP lease or static MAC-to-IP reservation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DhcpLease {
    pub lease_id: String,
    pub subnet_id: String,
    pub mac_address: String,
    pub hostname: String,
    pub fqdn: String,
    pub ip_address: Ipv4Addr,
    pub static_reservation: bool,
    pub issued_at: String,
    pub expires_at: String,
}

impl DhcpLease {
    /// Validates lease MAC, hostname, and domain fields.
    pub fn validate(&self) -> Result<(), String> {
        validate_policy_id(&self.subnet_id)?;
        validate_mac_address(&self.mac_address)?;
        validate_hostname(&self.hostname)?;
        validate_domain_name(&self.fqdn)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_and_subnet_validation_enforces_canonical_format_and_cidr_bounds() {
        assert_eq!(
            validate_mac_address("AA-BB-CC-DD-EE-01").unwrap(),
            "aa:bb:cc:dd:ee:01"
        );
        assert!(validate_mac_address("00:00:00:00:00:00").is_err());
        assert!(validate_mac_address("ff:ff:ff:ff:ff:ff").is_err());
        assert!(validate_mac_address("invalid").is_err());

        let subnet = IpamSubnet {
            id: "corp-lan".into(),
            domain: "corp.eu".into(),
            cidr: "10.42.0.0/24".into(),
            gateway: Ipv4Addr::new(10, 42, 0, 1),
            dns_servers: vec![Ipv4Addr::new(10, 42, 0, 1)],
            pool_start: Ipv4Addr::new(10, 42, 0, 50),
            pool_end: Ipv4Addr::new(10, 42, 0, 200),
            default_lease_seconds: 3600,
        };
        assert!(subnet.validate().is_ok());
        assert!(subnet.contains_pool_ip(Ipv4Addr::new(10, 42, 0, 100)));
        assert!(!subnet.contains_pool_ip(Ipv4Addr::new(10, 42, 0, 1)));
        assert!(!subnet.contains_pool_ip(Ipv4Addr::new(10, 42, 1, 100)));
    }
}
