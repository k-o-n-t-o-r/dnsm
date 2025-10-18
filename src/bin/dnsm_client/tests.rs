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
fn parse_ok_with_delays() {
    let args = ClientArgs::try_parse_from([
        "dnsm-client",
        "example.com",
        "--delay-ms",
        "10",
        "--await-reply-ms",
        "5",
        "--resolver-ip",
        "8.8.8.8",
    ])
    .expect("should parse");
    assert_eq!(args.zone, "example.com");
    assert_eq!(args.delay_ms, 10);
    assert_eq!(args.await_reply_ms, 5);
    assert_eq!(args.resolver_ip.as_deref(), Some("8.8.8.8"));
}

#[test]
fn random_mailbox_flag_sets_field() {
    let args = ClientArgs::try_parse_from(["dnsm-client", "example.com", "--random-mailbox"])
        .expect("should parse");
    assert!(args.random_mailbox);
    assert!(args.mailbox.is_none());
}

#[test]
fn random_mailbox_conflicts_with_mailbox() {
    let res = ClientArgs::try_parse_from([
        "dnsm-client",
        "example.com",
        "--mailbox",
        "abcdef123456",
        "--random-mailbox",
    ]);
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
