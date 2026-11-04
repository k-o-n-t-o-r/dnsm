use crate::{ChunkHeader, base32_nopad_decode, to_lower_labels};

pub const DNS_HEADER_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsParseError {
    Truncated,
    CompressedQuestion,
    InvalidLabel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedCarrier {
    pub header: ChunkHeader,
    pub bytes: Vec<u8>,
    pub payload_offset: usize,
    pub message_key: Option<u64>,
    pub mailbox: Option<u64>,
    pub base32_chars: usize,
    pub data_labels: usize,
}

impl DecodedCarrier {
    pub fn payload(&self) -> &[u8] {
        &self.bytes[self.payload_offset..]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CarrierDecodeError {
    OutsideZone,
    InvalidLabel { index: usize, label: String },
    InvalidBase32 { chars: usize, labels: usize },
    ShortHeader { len: usize },
    MissingMessageKey,
    MissingMailbox,
}

impl CarrierDecodeError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::OutsideZone => "outside_zone",
            Self::InvalidLabel { .. } => "invalid_label",
            Self::InvalidBase32 { .. } => "invalid_base32",
            Self::ShortHeader { .. } => "short_bytes",
            Self::MissingMessageKey => "missing_message_key",
            Self::MissingMailbox => "missing_mailbox",
        }
    }
}

pub fn read_u16(be: &[u8]) -> u16 {
    u16::from_be_bytes([be[0], be[1]])
}

pub fn write_u16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_be_bytes());
}

pub fn parse_header(packet: &[u8]) -> Result<DnsHeader, DnsParseError> {
    if packet.len() < DNS_HEADER_LEN {
        return Err(DnsParseError::Truncated);
    }
    Ok(DnsHeader {
        id: read_u16(&packet[0..2]),
        flags: read_u16(&packet[2..4]),
    })
}

/// Parse one DNS question and return `(domain, offset_after_qclass, qtype, qclass)`.
pub fn parse_question(packet: &[u8]) -> Result<(String, usize, u16, u16), DnsParseError> {
    if packet.len() < DNS_HEADER_LEN + 5 {
        return Err(DnsParseError::Truncated);
    }
    let mut offset = DNS_HEADER_LEN;
    let mut labels = Vec::new();
    loop {
        if offset >= packet.len() {
            return Err(DnsParseError::Truncated);
        }
        let raw = packet[offset];
        if raw & 0xC0 != 0 {
            return Err(DnsParseError::CompressedQuestion);
        }
        let len = raw as usize;
        offset += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return Err(DnsParseError::InvalidLabel);
        }
        if offset + len > packet.len() {
            return Err(DnsParseError::Truncated);
        }
        let label = std::str::from_utf8(&packet[offset..offset + len])
            .map_err(|_| DnsParseError::InvalidLabel)?;
        if label.contains('.') {
            return Err(DnsParseError::InvalidLabel);
        }
        labels.push(label.to_string());
        offset += len;
    }
    if offset + 4 > packet.len() {
        return Err(DnsParseError::Truncated);
    }
    let qtype = read_u16(&packet[offset..offset + 2]);
    let qclass = read_u16(&packet[offset + 2..offset + 4]);
    offset += 4;
    Ok((labels.join("."), offset, qtype, qclass))
}

pub fn strip_zone<'a>(labels: &'a [String], zone: &Option<Vec<String>>) -> Option<&'a [String]> {
    let zone = zone.as_ref()?;
    if labels.len() < zone.len() {
        return None;
    }
    let tail = &labels[labels.len() - zone.len()..];
    if tail != zone.as_slice() {
        return None;
    }
    let head = &labels[..labels.len() - zone.len()];
    (!head.is_empty()).then_some(head)
}

pub fn decode_carrier_domain(
    full_domain: &str,
    zone: &Option<Vec<String>>,
) -> Result<DecodedCarrier, CarrierDecodeError> {
    let labels = to_lower_labels(full_domain);
    let data_labels = strip_zone(&labels, zone).ok_or(CarrierDecodeError::OutsideZone)?;
    let mut encoded = String::with_capacity(data_labels.iter().map(String::len).sum());
    for (index, label) in data_labels.iter().enumerate() {
        if !label
            .chars()
            .all(|c| matches!(c, 'a'..='z' | 'A'..='Z' | '2'..='7' | '='))
        {
            return Err(CarrierDecodeError::InvalidLabel {
                index,
                label: label.clone(),
            });
        }
        encoded.push_str(label);
    }
    let bytes = base32_nopad_decode(&encoded).ok_or(CarrierDecodeError::InvalidBase32 {
        chars: encoded.len(),
        labels: data_labels.len(),
    })?;
    let (header, header_len) = ChunkHeader::from_bytes(&bytes)
        .ok_or(CarrierDecodeError::ShortHeader { len: bytes.len() })?;
    let mut payload_offset = header_len;
    let mut message_key = None;
    let mut mailbox = None;

    if header.is_ping || !header.chunked {
        if header.has_mailbox {
            mailbox =
                Some(read_u48(&bytes, payload_offset).ok_or(CarrierDecodeError::MissingMailbox)?);
            payload_offset += 6;
        } else if header.is_ping {
            return Err(CarrierDecodeError::MissingMailbox);
        }
    } else {
        message_key =
            Some(read_u48(&bytes, payload_offset).ok_or(CarrierDecodeError::MissingMessageKey)?);
        payload_offset += 6;
        if header.is_first && header.has_mailbox {
            mailbox =
                Some(read_u48(&bytes, payload_offset).ok_or(CarrierDecodeError::MissingMailbox)?);
            payload_offset += 6;
        }
    }

    Ok(DecodedCarrier {
        header,
        bytes,
        payload_offset,
        message_key,
        mailbox,
        base32_chars: encoded.len(),
        data_labels: data_labels.len(),
    })
}

fn read_u48(bytes: &[u8], offset: usize) -> Option<u64> {
    let value = bytes.get(offset..offset + 6)?;
    let mut out = [0u8; 8];
    out[2..].copy_from_slice(value);
    Some(u64::from_be_bytes(out))
}

pub fn has_edns(packet: &[u8], question_end: usize) -> bool {
    if packet.len() < DNS_HEADER_LEN {
        return false;
    }
    let additional = read_u16(&packet[10..12]);
    if additional == 0 {
        return false;
    }
    let record_count =
        read_u16(&packet[6..8]) as usize + read_u16(&packet[8..10]) as usize + additional as usize;
    let mut offset = question_end;
    for _ in 0..record_count {
        loop {
            if offset >= packet.len() {
                return false;
            }
            let byte = packet[offset];
            if byte == 0 {
                offset += 1;
                break;
            }
            if byte & 0xC0 == 0xC0 {
                offset += 2;
                break;
            }
            offset += 1 + byte as usize;
        }
        if offset + 10 > packet.len() {
            return false;
        }
        let record_type = read_u16(&packet[offset..offset + 2]);
        if record_type == 41 {
            return true;
        }
        let data_len = read_u16(&packet[offset + 8..offset + 10]) as usize;
        offset += 10 + data_len;
    }
    false
}

pub fn append_opt(response: &mut Vec<u8>, udp_payload_size: u16) {
    response.push(0);
    write_u16(response, 41);
    write_u16(response, udp_payload_size);
    response.extend_from_slice(&[0, 0, 0, 0]);
    write_u16(response, 0);
    let additional = read_u16(&response[10..12]).wrapping_add(1);
    response[10] = (additional >> 8) as u8;
    response[11] = additional as u8;
}

pub fn validate_and_sanitize_domain(domain: &str) -> Result<String, String> {
    const MAX_DOMAIN_LENGTH: usize = 255;
    const MAX_LABEL_LENGTH: usize = 63;
    const MAX_LABEL_COUNT: usize = 127;

    if domain.is_empty() {
        return Err("empty domain".to_string());
    }
    if domain.len() > MAX_DOMAIN_LENGTH {
        return Err(format!(
            "domain too long ({} bytes, max {})",
            domain.len(),
            MAX_DOMAIN_LENGTH
        ));
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() > MAX_LABEL_COUNT {
        return Err(format!(
            "too many labels ({}, max {})",
            labels.len(),
            MAX_LABEL_COUNT
        ));
    }
    for (index, label) in labels.iter().enumerate() {
        if label.is_empty() {
            if index != labels.len() - 1 {
                return Err(format!("empty label at position {index}"));
            }
            continue;
        }
        if label.len() > MAX_LABEL_LENGTH {
            return Err(format!(
                "label '{}' too long ({} bytes, max {})",
                label,
                label.len(),
                MAX_LABEL_LENGTH
            ));
        }
        for (char_index, ch) in label.chars().enumerate() {
            if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' {
                if ch.is_control() {
                    return Err(format!("control character (0x{:02x}) in label", ch as u32));
                }
                return Err(format!("invalid character '{ch}' in label"));
            }
            if ch == '-' && (char_index == 0 || char_index == label.len() - 1) {
                return Err("label cannot start/end with hyphen".to_string());
            }
        }
    }
    Ok(domain.to_string())
}

pub fn sanitize_domain_for_logging(domain: &str) -> String {
    const MAX_LOG_LENGTH: usize = 255;
    let truncated = if domain.len() > MAX_LOG_LENGTH {
        domain
            .get(..MAX_LOG_LENGTH)
            .unwrap_or_else(|| &domain[..domain.floor_char_boundary(MAX_LOG_LENGTH)])
    } else {
        domain
    };
    truncated
        .chars()
        .map(|ch| {
            if ch.is_control() || !ch.is_ascii() {
                '?'
            } else {
                ch
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BuildOptions, build_domains_for_data};

    fn build_query(domain: &str) -> Vec<u8> {
        let mut packet = Vec::new();
        write_u16(&mut packet, 0x1234);
        write_u16(&mut packet, 0x0100);
        write_u16(&mut packet, 1);
        write_u16(&mut packet, 0);
        write_u16(&mut packet, 0);
        write_u16(&mut packet, 0);
        for label in domain.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        write_u16(&mut packet, 1);
        write_u16(&mut packet, 1);
        packet
    }

    #[test]
    fn question_parser_roundtrips_domain() {
        let packet = build_query("www.example");
        let header = parse_header(&packet).unwrap();
        let (domain, _, qtype, qclass) = parse_question(&packet).unwrap();
        assert_eq!(header.id, 0x1234);
        assert_eq!(domain, "www.example");
        assert_eq!((qtype, qclass), (1, 1));
    }

    #[test]
    fn carrier_decoder_extracts_header_mailbox_and_payload() {
        let options = BuildOptions {
            mailbox: Some(0x0102_0304_0506),
        };
        let (domains, _) = build_domains_for_data(b"hello", "x.example", &options).unwrap();
        let zone = Some(vec!["x".to_string(), "example".to_string()]);
        let decoded = decode_carrier_domain(&domains[0], &zone).unwrap();
        assert!(decoded.header.has_mailbox);
        assert_eq!(decoded.mailbox, options.mailbox);
        assert!(!decoded.payload().is_empty());
    }

    #[test]
    fn invalid_carrier_label_is_rejected() {
        let zone = Some(vec!["x".to_string(), "example".to_string()]);
        let error = decode_carrier_domain("bad!.x.example", &zone).unwrap_err();
        assert!(matches!(error, CarrierDecodeError::InvalidLabel { .. }));
    }
}
