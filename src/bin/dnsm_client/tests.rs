use super::*;
use clap::error::ErrorKind;

#[test]
fn help_flag_triggers_help() {
    let res = ClientArgs::try_parse_from(["dnsm-client", "--help"]);
    assert!(res.is_err());
    let e = res.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::DisplayHelp);
}

#[test]
fn zone_defaults_to_k_dnsm_re() {
    let args = ClientArgs::try_parse_from(["dnsm-client"]).expect("should parse");
    assert_eq!(args.zone, "k.dnsm.re");
    assert!(args.mailbox.is_none());
}

#[test]
fn custom_zone() {
    let args = ClientArgs::try_parse_from([
        "dnsm-client",
        "--zone",
        "x.foo.bar",
        "--delay-ms",
        "10",
        "--await-reply-ms",
        "5",
        "--resolver-ip",
        "8.8.8.8",
    ])
    .expect("should parse");
    assert_eq!(args.zone, "x.foo.bar");
    assert_eq!(args.delay_ms, 10);
    assert_eq!(args.await_reply_ms, 5);
    assert_eq!(args.resolver_ip.as_deref(), Some("8.8.8.8"));
}

#[test]
fn positional_mailbox_parsed() {
    let args = ClientArgs::try_parse_from(["dnsm-client", "abcdef123456"]).expect("should parse");
    assert_eq!(args.mailbox.as_deref(), Some("abcdef123456"));
    assert_eq!(args.zone, "k.dnsm.re");
}

#[test]
fn invalid_positional_mailbox_rejected() {
    let res = ClientArgs::try_parse_from(["dnsm-client", "not-a-hex"]);
    assert!(res.is_err());
}

#[test]
fn await_reply_ms_defaults_to_3000() {
    let args = ClientArgs::try_parse_from(["dnsm-client"]).expect("should parse");
    assert_eq!(args.await_reply_ms, 3000);
}

#[test]
fn random_mailbox_flag_sets_field() {
    let args =
        ClientArgs::try_parse_from(["dnsm-client", "--random-mailbox"]).expect("should parse");
    assert!(args.random_mailbox);
    assert!(args.mailbox.is_none());
}

#[test]
fn random_mailbox_conflicts_with_positional() {
    let res = ClientArgs::try_parse_from(["dnsm-client", "abcdef123456", "--random-mailbox"]);
    assert!(res.is_err());
    let e = res.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::ArgumentConflict);
}

#[test]
fn ipv6_target_formatting() {
    assert_eq!(to_target_addr("2001:db8::1"), "[2001:db8::1]:53");
    assert_eq!(to_target_addr("[2001:db8::1]"), "[2001:db8::1]:53");
    assert_eq!(to_target_addr("[2001:db8::1]:5353"), "[2001:db8::1]:5353");
    assert_eq!(to_target_addr("8.8.8.8"), "8.8.8.8:53");
    assert_eq!(to_target_addr("dns.google:853"), "dns.google:853");
}

fn build_test_response(id: u16, rcode: u8, ip: Option<Ipv4Addr>) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&id.to_be_bytes());
    let flags: u16 = 0x8000 | (rcode as u16);
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    let ancount: u16 = if ip.is_some() { 1 } else { 0 };
    buf.extend_from_slice(&ancount.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    // Question: "test.example" TYPE A CLASS IN
    for label in ["test", "example"] {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    buf.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
    buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    if let Some(addr) = ip {
        // Answer RR with compression pointer to QNAME
        buf.extend_from_slice(&[0xC0, 0x0C]); // pointer to offset 12
        buf.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        buf.extend_from_slice(&60u32.to_be_bytes()); // TTL
        buf.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        buf.extend_from_slice(&addr.octets());
    }
    buf
}

#[test]
fn parse_response_extracts_a_record() {
    let ip = Ipv4Addr::new(192, 0, 2, 1);
    let buf = build_test_response(0x1234, 0, Some(ip));
    let resp = parse_dns_response(&buf, buf.len()).expect("should parse");
    assert_eq!(resp.id, 0x1234);
    assert_eq!(resp.rcode, 0);
    assert_eq!(resp.answer_ip, Some(ip));
}

#[test]
fn parse_response_no_answer() {
    let buf = build_test_response(0xABCD, 0, None);
    let resp = parse_dns_response(&buf, buf.len()).expect("should parse");
    assert_eq!(resp.id, 0xABCD);
    assert_eq!(resp.rcode, 0);
    assert_eq!(resp.answer_ip, None);
}

#[test]
fn parse_response_nxdomain() {
    let buf = build_test_response(0x5678, 3, None);
    let resp = parse_dns_response(&buf, buf.len()).expect("should parse");
    assert_eq!(resp.rcode, 3);
}

#[test]
fn parse_response_too_short() {
    assert!(parse_dns_response(&[0; 4], 4).is_none());
}

#[test]
fn parse_response_truncated_qname() {
    let mut buf = vec![0u8; 12];
    buf[0..2].copy_from_slice(&0x1111u16.to_be_bytes());
    buf[2..4].copy_from_slice(&0x8000u16.to_be_bytes());
    buf[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    // QNAME label claims 50 bytes but buffer ends here
    buf.push(50);
    assert!(parse_dns_response(&buf, buf.len()).is_none());
}

#[test]
fn parse_response_truncated_compression_pointer() {
    let mut buf = vec![0u8; 12];
    buf[0..2].copy_from_slice(&0x2222u16.to_be_bytes());
    buf[2..4].copy_from_slice(&0x8000u16.to_be_bytes());
    buf[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    // Compression pointer byte but no second byte
    buf.push(0xC0);
    assert!(parse_dns_response(&buf, buf.len()).is_none());
}

#[test]
fn parse_response_oversized_rdlength() {
    let mut buf = build_test_response(0x3333, 0, Some(Ipv4Addr::new(1, 2, 3, 4)));
    // Corrupt RDLENGTH to claim 999 bytes
    let rdlen_pos = buf.len() - 4 - 2; // 4 bytes RDATA + 2 bytes RDLENGTH
    buf[rdlen_pos..rdlen_pos + 2].copy_from_slice(&999u16.to_be_bytes());
    let resp = parse_dns_response(&buf, buf.len()).expect("should parse header");
    // Should not extract an IP since RDLENGTH overflows the buffer
    assert_eq!(resp.answer_ip, None);
}
