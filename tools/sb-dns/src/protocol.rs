use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RecordType {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    ANY = 255,
}

impl RecordType {
    pub fn from_u16(val: u16) -> Self {
        match val {
            1 => RecordType::A,
            2 => RecordType::NS,
            5 => RecordType::CNAME,
            6 => RecordType::SOA,
            12 => RecordType::PTR,
            15 => RecordType::MX,
            16 => RecordType::TXT,
            28 => RecordType::AAAA,
            _ => RecordType::ANY,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseCode {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsHeader {
    pub id: u16,
    pub recursion_desired: bool,
    pub truncated: bool,
    pub authoritative: bool,
    pub opcode: u8,
    pub is_response: bool,
    pub response_code: ResponseCode,
    pub checking_disabled: bool,
    pub authed_data: bool,
    pub z: bool,
    pub recursion_available: bool,
    pub questions_count: u16,
    pub answers_count: u16,
    pub authorities_count: u16,
    pub additionals_count: u16,
}

impl Default for DnsHeader {
    fn default() -> Self {
        Self {
            id: 0,
            recursion_desired: false,
            truncated: false,
            authoritative: false,
            opcode: 0,
            is_response: false,
            response_code: ResponseCode::NoError,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,
            questions_count: 0,
            answers_count: 0,
            authorities_count: 0,
            additionals_count: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: RecordType,
    pub qclass: u16,
}

impl DnsQuestion {
    pub fn new(name: &str, qtype: RecordType) -> Self {
        Self {
            name: name.to_string(),
            qtype,
            qclass: 1, // IN
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(String),
    TXT(String),
    PTR(String),
    Raw(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: RecordType,
    pub class: u16,
    pub ttl: u32,
    pub data: RecordData,
}

impl DnsRecord {
    pub fn a(name: &str, ip: Ipv4Addr, ttl: u32) -> Self {
        Self {
            name: name.to_string(),
            rtype: RecordType::A,
            class: 1,
            ttl,
            data: RecordData::A(ip),
        }
    }

    pub fn aaaa(name: &str, ip: Ipv6Addr, ttl: u32) -> Self {
        Self {
            name: name.to_string(),
            rtype: RecordType::AAAA,
            class: 1,
            ttl,
            data: RecordData::AAAA(ip),
        }
    }

    pub fn cname(name: &str, target: &str, ttl: u32) -> Self {
        Self {
            name: name.to_string(),
            rtype: RecordType::CNAME,
            class: 1,
            ttl,
            data: RecordData::CNAME(target.to_string()),
        }
    }

    pub fn txt(name: &str, text: &str, ttl: u32) -> Self {
        Self {
            name: name.to_string(),
            rtype: RecordType::TXT,
            class: 1,
            ttl,
            data: RecordData::TXT(text.to_string()),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn make_response(&self, code: ResponseCode, authoritative: bool) -> Self {
        let mut resp = Self::new();
        resp.header.id = self.header.id;
        resp.header.is_response = true;
        resp.header.authoritative = authoritative;
        resp.header.response_code = code;
        resp.header.recursion_desired = self.header.recursion_desired;
        resp.header.recursion_available = true;
        resp.questions = self.questions.clone();
        resp
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // ID
        buf.extend_from_slice(&self.header.id.to_be_bytes());

        // Flags byte 1
        let mut b1 = 0u8;
        if self.header.is_response {
            b1 |= 0x80;
        }
        b1 |= (self.header.opcode & 0x0F) << 3;
        if self.header.authoritative {
            b1 |= 0x04;
        }
        if self.header.truncated {
            b1 |= 0x02;
        }
        if self.header.recursion_desired {
            b1 |= 0x01;
        }
        buf.push(b1);

        // Flags byte 2
        let mut b2 = 0u8;
        if self.header.recursion_available {
            b2 |= 0x80;
        }
        b2 |= (self.header.response_code as u8) & 0x0F;
        buf.push(b2);

        // Counts
        buf.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.authorities.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.resources.len() as u16).to_be_bytes());

        // Questions
        for q in &self.questions {
            for part in q.name.split('.') {
                if !part.is_empty() {
                    buf.push(part.len() as u8);
                    buf.extend_from_slice(part.as_bytes());
                }
            }
            buf.push(0); // Root label
            buf.extend_from_slice(&(q.qtype as u16).to_be_bytes());
            buf.extend_from_slice(&q.qclass.to_be_bytes());
        }

        // Answers
        for a in &self.answers {
            for part in a.name.split('.') {
                if !part.is_empty() {
                    buf.push(part.len() as u8);
                    buf.extend_from_slice(part.as_bytes());
                }
            }
            buf.push(0);
            buf.extend_from_slice(&(a.rtype as u16).to_be_bytes());
            buf.extend_from_slice(&a.class.to_be_bytes());
            buf.extend_from_slice(&a.ttl.to_be_bytes());

            match &a.data {
                RecordData::A(ip) => {
                    buf.extend_from_slice(&4u16.to_be_bytes());
                    buf.extend_from_slice(&ip.octets());
                }
                RecordData::AAAA(ip) => {
                    buf.extend_from_slice(&16u16.to_be_bytes());
                    buf.extend_from_slice(&ip.octets());
                }
                RecordData::TXT(t) => {
                    let b = t.as_bytes();
                    buf.extend_from_slice(&((b.len() + 1) as u16).to_be_bytes());
                    buf.push(b.len() as u8);
                    buf.extend_from_slice(b);
                }
                RecordData::CNAME(c) | RecordData::PTR(c) => {
                    let mut name_bytes = Vec::new();
                    for part in c.split('.') {
                        if !part.is_empty() {
                            name_bytes.push(part.len() as u8);
                            name_bytes.extend_from_slice(part.as_bytes());
                        }
                    }
                    name_bytes.push(0);
                    buf.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
                    buf.extend_from_slice(&name_bytes);
                }
                RecordData::Raw(r) => {
                    buf.extend_from_slice(&(r.len() as u16).to_be_bytes());
                    buf.extend_from_slice(r);
                }
            }
        }

        buf
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 12 {
            return Err("Packet too short".into());
        }

        let mut packet = Self::new();
        packet.header.id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let b1 = bytes[2];
        let b2 = bytes[3];

        packet.header.is_response = (b1 & 0x80) != 0;
        packet.header.opcode = (b1 >> 3) & 0x0F;
        packet.header.authoritative = (b1 & 0x04) != 0;
        packet.header.truncated = (b1 & 0x02) != 0;
        packet.header.recursion_desired = (b1 & 0x01) != 0;
        packet.header.recursion_available = (b2 & 0x80) != 0;
        packet.header.response_code = match b2 & 0x0F {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormatError,
            2 => ResponseCode::ServerFailure,
            3 => ResponseCode::NameError,
            4 => ResponseCode::NotImplemented,
            _ => ResponseCode::Refused,
        };

        let q_count = u16::from_be_bytes([bytes[4], bytes[5]]);
        let a_count = u16::from_be_bytes([bytes[6], bytes[7]]);

        let mut pos = 12;

        // Parse questions
        for _ in 0..q_count {
            let (name, new_pos) = read_name(bytes, pos)?;
            pos = new_pos;
            if pos + 4 > bytes.len() {
                return Err("Truncated question".into());
            }
            let qtype = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
            let qclass = u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]);
            pos += 4;
            packet.questions.push(DnsQuestion {
                name,
                qtype: RecordType::from_u16(qtype),
                qclass,
            });
        }

        // Parse answers
        for _ in 0..a_count {
            if pos >= bytes.len() {
                break;
            }
            let (name, new_pos) = read_name(bytes, pos)?;
            pos = new_pos;
            if pos + 10 > bytes.len() {
                break;
            }
            let rtype = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
            let class = u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]);
            let ttl = u32::from_be_bytes([
                bytes[pos + 4],
                bytes[pos + 5],
                bytes[pos + 6],
                bytes[pos + 7],
            ]);
            let rdlen = u16::from_be_bytes([bytes[pos + 8], bytes[pos + 9]]) as usize;
            pos += 10;

            if pos + rdlen > bytes.len() {
                break;
            }
            let rdata_bytes = &bytes[pos..pos + rdlen];
            pos += rdlen;

            let data = match RecordType::from_u16(rtype) {
                RecordType::A if rdlen == 4 => RecordData::A(Ipv4Addr::new(
                    rdata_bytes[0],
                    rdata_bytes[1],
                    rdata_bytes[2],
                    rdata_bytes[3],
                )),
                RecordType::AAAA if rdlen == 16 => {
                    let mut oct = [0u8; 16];
                    oct.copy_from_slice(rdata_bytes);
                    RecordData::AAAA(Ipv6Addr::from(oct))
                }
                RecordType::CNAME => {
                    let (cname, _) = read_name(bytes, pos - rdlen).unwrap_or((String::new(), 0));
                    RecordData::CNAME(cname)
                }
                RecordType::TXT => {
                    let text = String::from_utf8_lossy(&rdata_bytes[1..]).to_string();
                    RecordData::TXT(text)
                }
                _ => RecordData::Raw(rdata_bytes.to_vec()),
            };

            packet.answers.push(DnsRecord {
                name,
                rtype: RecordType::from_u16(rtype),
                class,
                ttl,
                data,
            });
        }

        Ok(packet)
    }
}

fn read_name(bytes: &[u8], mut pos: usize) -> Result<(String, usize), String> {
    let mut parts = Vec::new();
    let mut jumped = false;
    let mut return_pos = pos;

    loop {
        if pos >= bytes.len() {
            return Err("Name out of bounds".into());
        }
        let len = bytes[pos];
        if (len & 0xC0) == 0xC0 {
            // Pointer
            if pos + 1 >= bytes.len() {
                return Err("Pointer truncated".into());
            }
            let ptr = (((len & 0x3F) as usize) << 8) | (bytes[pos + 1] as usize);
            if !jumped {
                return_pos = pos + 2;
                jumped = true;
            }
            pos = ptr;
            continue;
        }

        pos += 1;
        if len == 0 {
            break;
        }

        if pos + (len as usize) > bytes.len() {
            return Err("Label out of bounds".into());
        }

        let label = String::from_utf8_lossy(&bytes[pos..pos + (len as usize)]).to_string();
        parts.push(label);
        pos += len as usize;
    }

    if !jumped {
        return_pos = pos;
    }

    Ok((parts.join("."), return_pos))
}
