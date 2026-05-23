from __future__ import annotations

import argparse
import random
import secrets
import socket
import struct
import sys
import time

import dnsm


def _parse_resolv_conf() -> str | None:
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                if line.startswith("nameserver"):
                    host = line.split()[1] if len(line.split()) > 1 else None
                    if host:
                        return host
    except OSError:
        pass
    return None


def _to_target_addr(host_or_ip: str) -> tuple[str, int]:
    if host_or_ip.startswith("["):
        idx = host_or_ip.find("]")
        if idx != -1 and host_or_ip[idx:].startswith("]:"):
            return host_or_ip[1:idx], int(host_or_ip[idx + 2 :])
        addr = host_or_ip.strip("[]")
        return addr, 53
    try:
        socket.inet_pton(socket.AF_INET6, host_or_ip)
        return host_or_ip, 53
    except OSError:
        pass
    if ":" in host_or_ip:
        host, port = host_or_ip.rsplit(":", 1)
        return host, int(port)
    return host_or_ip, 53


def _build_query(domain: str) -> bytes:
    qid = random.randint(0, 0xFFFF)
    buf = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in domain.split("."):
        encoded = label.encode()
        buf += bytes([len(encoded)]) + encoded
    buf += b"\x00"
    buf += struct.pack(">HH", 1, 1)  # TYPE A, CLASS IN
    return buf


def _validate_mailbox(value: str) -> str:
    s = value.strip()
    if len(s) != 12 or not all(c in "0123456789abcdefABCDEF" for c in s):
        raise argparse.ArgumentTypeError(
            f"invalid mailbox '{value}': expected exactly 12 hex chars (no 0x)"
        )
    return s.lower()


def _skip_dns_name(buf: bytes, start: int) -> int | None:
    off = start
    while True:
        if off >= len(buf):
            return None
        b = buf[off]
        if b == 0:
            return off + 1
        if b & 0xC0 == 0xC0:
            if off + 2 > len(buf):
                return None
            return off + 2
        off += 1 + b


def _parse_dns_response(buf: bytes) -> tuple[int, int, str | None] | None:
    if len(buf) < 12:
        return None
    qid = struct.unpack(">H", buf[:2])[0]
    flags = struct.unpack(">H", buf[2:4])[0]
    rcode = flags & 0x000F
    ancount = struct.unpack(">H", buf[6:8])[0]
    off = _skip_dns_name(buf, 12)
    if off is None or off + 4 > len(buf):
        return None
    off += 4  # QTYPE + QCLASS
    answer_ip = None
    for _ in range(ancount):
        off = _skip_dns_name(buf, off)
        if off is None:
            break
        if off + 10 > len(buf):
            break
        rtype = struct.unpack(">H", buf[off : off + 2])[0]
        rdlen = struct.unpack(">H", buf[off + 8 : off + 10])[0]
        off += 10
        if off + rdlen > len(buf):
            break
        if rtype == 1 and rdlen == 4 and answer_ip is None:
            answer_ip = f"{buf[off]}.{buf[off+1]}.{buf[off+2]}.{buf[off+3]}"
        off += rdlen
    return (qid, rcode, answer_ip)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="dnsm-client",
        description="Send data via DNS queries",
        epilog=(
            "Examples:\n"
            "  echo 'hello' | dnsm-client\n"
            "  echo 'hello' | dnsm-client abcdef123456\n"
            "  echo 'hello' | dnsm-client abcdef123456 --zone x.foo.bar -n\n"
            "  dnsm-client --ping\n"
            "  head -c 200000 /dev/urandom | dnsm-client --resolver-ip 127.0.0.1:5353"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "mailbox",
        nargs="?",
        metavar="MAILBOX",
        type=_validate_mailbox,
        default=None,
        help="Mailbox ID (exactly 12 hex chars). Random if omitted.",
    )
    parser.add_argument(
        "--zone",
        metavar="ZONE",
        default="k.dnsm.re",
        help="Zone/apex the payload labels are appended to (default: k.dnsm.re)",
    )
    parser.add_argument(
        "--resolver-ip",
        metavar="HOST[:PORT]",
        help="Send to this resolver (default: first nameserver in /etc/resolv.conf)",
    )
    parser.add_argument(
        "-n",
        "--dont-query",
        action="store_true",
        help="Do not send; print hostnames (one per chunk)",
    )
    parser.add_argument(
        "--await-reply-ms",
        metavar="MS",
        type=int,
        default=3000,
        help="Wait up to this many ms for a reply (0 disables, default: 3000)",
    )
    parser.add_argument(
        "--delay-ms",
        metavar="MS",
        type=int,
        default=5,
        help="Sleep this many ms between queries",
    )
    parser.add_argument(
        "--sent-log",
        metavar="PATH",
        help="Append a human-readable send log to this file",
    )
    parser.add_argument(
        "--random-mailbox", action="store_true", help="Generate a random mailbox ID"
    )
    parser.add_argument(
        "--ping", action="store_true", help="Send a minimal ping"
    )
    parser.add_argument(
        "--debug", action="store_true", help="Verbose progress to stderr"
    )
    parser.add_argument(
        "-p",
        "--pretty",
        action="store_true",
        help="Print colored send progress to stderr",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    parser.add_argument(
        "--tagged-log",
        action="store_true",
        help="Also write bracketed tags to --sent-log",
    )

    args = parser.parse_args(argv)

    if args.random_mailbox and args.mailbox:
        parser.error("--random-mailbox conflicts with positional MAILBOX")

    use_color = args.pretty and not args.no_color

    def _styled(tag: str, color: str, bold: bool = True) -> str:
        codes = {"green": "32", "cyan": "36", "yellow": "33", "white": "37", "dim": "2"}
        if not use_color:
            return tag
        prefix = "1;" if bold else ""
        code = codes.get(color, "0")
        if color == "dim":
            return f"\033[2m{tag}\033[0m"
        return f"\033[{prefix}{code}m{tag}\033[0m"

    if args.mailbox:
        mailbox_hex = args.mailbox
    else:
        mailbox_hex = secrets.token_hex(6)

    # --- Ping mode ---
    if args.ping:
        try:
            domain = dnsm.build_human_ping_domain(mailbox_hex, args.zone)
        except ValueError as e:
            print(f"dnsm-client: {e}", file=sys.stderr)
            sys.exit(2)
        print(
            f"dnsm-client: zone={args.zone} ping mailbox={mailbox_hex}",
            file=sys.stderr,
        )
        if args.dont_query:
            print(domain)
            return
        host, port = _resolve_target(args.resolver_ip)
        if host is None:
            print(domain)
            return
        _send_ping(domain, host, port, args, _styled)
        if args.zone == "k.dnsm.re":
            print(f"\nInbox: https://dnsm.re/#/inbox/{mailbox_hex}", file=sys.stderr)
        return

    # --- Normal message mode ---
    stdin_data = sys.stdin.buffer.read()
    try:
        text = stdin_data.decode("utf-8")
        stdin_data = text.rstrip().encode("utf-8")
    except UnicodeDecodeError:
        pass

    try:
        domains, info = dnsm.build_domains(stdin_data, args.zone, mailbox_hex)
    except ValueError as e:
        print(f"dnsm-client: {e}", file=sys.stderr)
        sys.exit(2)

    sock = None
    logfile = None
    if args.sent_log:
        logfile = open(args.sent_log, "a")

    if not args.dont_query:
        host, port = _resolve_target(args.resolver_ip)
        if host is not None:
            target_str = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            try:
                addrinfo = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
                if not addrinfo:
                    raise OSError(f"cannot resolve {host}")
                family = addrinfo[0][0]
                addr = addrinfo[0][4]
                sock = socket.socket(family, socket.SOCK_DGRAM)
                sock.connect(addr)
                if args.await_reply_ms > 0:
                    sock.settimeout(args.await_reply_ms / 1000.0)
            except OSError as e:
                print(f"dnsm-client: connect {target_str}: {e}", file=sys.stderr)
                sys.exit(1)
            print(f"dnsm-client: sending via resolver {target_str}", file=sys.stderr)
            if args.pretty:
                print(
                    f"{_styled('[INFO]', 'cyan')} {_styled('resolver', 'cyan')} {_styled(target_str, 'cyan')}",
                    file=sys.stderr,
                )
        else:
            print(
                "dnsm-client: no --resolver-ip and could not parse /etc/resolv.conf; printing hostnames",
                file=sys.stderr,
            )

    if args.pretty:
        print(
            f"{_styled('[INFO]', 'cyan')} {_styled('zone', 'dim', False)}={_styled(args.zone, 'cyan')} "
            f"{_styled('first_payload', 'dim', False)}={_styled(str(info.first_payload_len), 'cyan')} "
            f"{_styled('payload_per_chunk', 'dim', False)}={_styled(str(info.payload_per_chunk), 'cyan')} "
            f"{_styled('total_chunks', 'dim', False)}={_styled(str(info.total_chunks), 'cyan')}",
            file=sys.stderr,
        )
        print(
            f"{_styled('[INFO]', 'cyan')} {_styled('mailbox', 'dim', False)}={_styled(mailbox_hex, 'cyan')}  "
            f"{_styled('View inbox at', 'white', False)} {_styled(f'https://dnsm.re/#/inbox/{mailbox_hex}', 'white')}",
            file=sys.stderr,
        )
        print(file=sys.stderr)
    else:
        print(
            f"dnsm-client: zone={args.zone} first_payload={info.first_payload_len} "
            f"payload_per_chunk={info.payload_per_chunk} total_chunks={info.total_chunks}"
            f" mailbox={mailbox_hex}",
            file=sys.stderr,
        )

    for i, qname in enumerate(domains):
        remaining = info.total_chunks - 1 - i
        if sock is not None:
            q = _build_query(qname)
            qid = struct.unpack(">H", q[:2])[0]
            if args.debug:
                print(
                    f"SEND idx={i} remaining={remaining} qname_len={len(qname)} "
                    f"labels={qname.count('.') + 1} id={qid}",
                    file=sys.stderr,
                )
            sock.send(q)

            ack_ok = False
            resp_ip = None
            if args.await_reply_ms > 0:
                try:
                    buf = sock.recv(512)
                    if len(buf) >= 12:
                        parsed = _parse_dns_response(buf)
                        if parsed and parsed[0] == qid and parsed[1] == 0:
                            ack_ok = True
                            resp_ip = parsed[2]
                except (socket.timeout, OSError):
                    pass

            if args.await_reply_ms > 0:
                ip_str = f" ip={resp_ip}" if resp_ip else ""
                if ack_ok:
                    if args.pretty:
                        print(
                            f"{_styled('[OK]', 'green')} {qname}{_styled(ip_str, 'dim', False)}",
                        )
                    else:
                        print(f"{qname} ok{ip_str}")
                else:
                    if args.pretty:
                        print(
                            f"{_styled('[TIMEOUT]', 'yellow')} {qname} after={args.await_reply_ms}ms",
                        )
                    else:
                        print(
                            f"{qname} timeout after={args.await_reply_ms}ms",
                        )
            elif args.pretty:
                print(
                    f"{_styled('[SEND]', 'green')} {qname}",
                )
            else:
                print(f"{qname} sent")

            if logfile:
                ack_str = (
                    "-" if args.await_reply_ms == 0 else ("ok" if ack_ok else "timeout")
                )
                logfile.write(
                    f"SENT idx={i} remaining={remaining} qname_len={len(qname)} "
                    f"labels={qname.count('.') + 1} id={qid} ack={ack_str} time_ms={args.await_reply_ms}\n"
                )
                if args.tagged_log:
                    logfile.write(
                        f"[SEND] idx={i} remaining={remaining} qname_len={len(qname)} "
                        f"labels={qname.count('.') + 1} id={qid}\n"
                    )
                    if args.await_reply_ms > 0:
                        tag = "[ACK]" if ack_ok else "[TIMEOUT]"
                        logfile.write(
                            f"{tag} id={qid} idx={i} after={args.await_reply_ms}ms\n"
                        )
                logfile.flush()

            if args.delay_ms > 0:
                time.sleep(args.delay_ms / 1000.0)
        else:
            print(qname)

    if logfile:
        logfile.close()
    if sock:
        sock.close()

    if args.zone == "k.dnsm.re":
        print(f"\nInbox: https://dnsm.re/#/inbox/{mailbox_hex}", file=sys.stderr)


def _resolve_target(resolver_ip: str | None) -> tuple[str | None, int]:
    if resolver_ip:
        host, port = _to_target_addr(resolver_ip)
        return host, port
    system = _parse_resolv_conf()
    if system:
        return _to_target_addr(system)
    return None, 53


def _send_ping(domain: str, host: str, port: int, args, _styled) -> None:
    target_str = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    try:
        addrinfo = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
        family = addrinfo[0][0]
        addr = addrinfo[0][4]
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.connect(addr)
        if args.await_reply_ms > 0:
            sock.settimeout(args.await_reply_ms / 1000.0)
    except OSError as e:
        print(f"dnsm-client: connect {target_str}: {e}", file=sys.stderr)
        sys.exit(1)

    q = _build_query(domain)
    qid = struct.unpack(">H", q[:2])[0]
    sock.send(q)
    if args.await_reply_ms > 0:
        try:
            buf = sock.recv(512)
            if len(buf) >= 12:
                parsed = _parse_dns_response(buf)
                if parsed and parsed[0] == qid and parsed[1] == 0:
                    ip_str = f" ip={parsed[2]}" if parsed[2] else ""
                    if args.pretty:
                        print(
                            f"{_styled('[OK]', 'green')} {domain}{_styled(ip_str, 'dim', False)}",
                        )
                    else:
                        print(f"{domain} ok{ip_str}")
                    sock.close()
                    return
        except (socket.timeout, OSError):
            pass
        if args.pretty:
            print(
                f"{_styled('[TIMEOUT]', 'yellow')} {domain} after={args.await_reply_ms}ms",
            )
        else:
            print(f"{domain} timeout after={args.await_reply_ms}ms")
    elif args.pretty:
        print(f"{_styled('[SEND]', 'green')} {domain}")
    else:
        print(f"{domain} sent")
    sock.close()


if __name__ == "__main__":
    main()
