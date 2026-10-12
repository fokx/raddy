use crate::context::ConnectionContext;
use ipnet::IpNet;
use raddy_core::config::*;
use regex::Regex;
use std::net::IpAddr;
use std::str::FromStr;

/// Evaluates whether a connection matches a given Layer4MatcherSet.
/// Matchers in the same set are evaluated in conjunction (AND logic).
pub fn matches_matcher_set(
    set: &Layer4MatcherSet,
    ctx: &mut ConnectionContext,
    buf: &[u8],
) -> bool {
    // 1. TLS Matcher
    if let Some(ref tls) = set.tls {
        if !matches_tls(tls, ctx, buf) {
            return false;
        }
    }

    // 2. HTTP Matcher
    if let Some(ref http) = set.http {
        if !matches_http(http, buf) {
            return false;
        }
    }

    // 3. SSH Matcher
    if set.ssh.is_some() {
        if !matches_ssh(buf) {
            return false;
        }
    }

    // 4. Proxy Protocol Matcher
    if set.proxy_protocol.is_some() {
        if !matches_proxy_protocol(buf) {
            return false;
        }
    }

    // 5. Remote IP Matcher
    if let Some(ref ip) = set.remote_ip.as_ref().or(set.ip.as_ref()) {
        if !matches_ip(&ip.ranges, ctx.remote_addr.ip()) {
            return false;
        }
    }

    // 6. Local IP Matcher
    if let Some(ref ip) = set.local_ip {
        if !matches_ip(&ip.ranges, ctx.local_addr.ip()) {
            return false;
        }
    }

    // 7. QUIC Matcher
    if set.quic.is_some() {
        if !matches_quic(buf) {
            return false;
        }
    }

    // 8. WireGuard Matcher
    if set.wireguard.is_some() {
        if !matches_wireguard(buf) {
            return false;
        }
    }

    // 9. SOCKS4 Matcher
    if set.socks4.is_some() {
        if !matches_socks4(buf) {
            return false;
        }
    }

    // 10. SOCKS5 Matcher
    if set.socks5.is_some() {
        if !matches_socks5(buf) {
            return false;
        }
    }

    // 11. Postgres Matcher
    if set.postgres.is_some() {
        if !matches_postgres(buf) {
            return false;
        }
    }

    // 12. OpenVPN Matcher
    if set.openvpn.is_some() {
        if !matches_openvpn(buf) {
            return false;
        }
    }

    // 13. RDP Matcher
    if set.rdp.is_some() {
        if !matches_rdp(buf) {
            return false;
        }
    }

    // 14. XMPP Matcher
    if set.xmpp.is_some() {
        if !matches_xmpp(buf) {
            return false;
        }
    }

    // 15. Regexp Matcher
    if let Some(ref pattern) = set.regexp {
        if let Ok(re) = Regex::new(pattern) {
            let text = String::from_utf8_lossy(buf);
            if !re.is_match(&text) {
                return false;
            }
        } else {
            return false;
        }
    }

    // 16. Not Matcher
    if let Some(ref not_sets) = set.not {
        for n_set in not_sets {
            if matches_matcher_set(n_set, ctx, buf) {
                return false;
            }
        }
    }

    // 17. Custom vars matcher (if present in extra)
    if let Some(vars_val) = set.extra.get("vars") {
        if let Some(obj) = vars_val.as_object() {
            for (k, v) in obj {
                let expected = v.as_str().unwrap_or("");
                if ctx.get_var(k).unwrap_or("") != expected {
                    return false;
                }
            }
        }
    }

    true
}

/// Checks if any matcher in a matcher set requires looking at payload data bytes.
pub fn requires_payload_data(set: &Layer4MatcherSet) -> bool {
    set.tls.is_some()
        || set.http.is_some()
        || set.ssh.is_some()
        || set.proxy_protocol.is_some()
        || set.quic.is_some()
        || set.wireguard.is_some()
        || set.socks4.is_some()
        || set.socks5.is_some()
        || set.postgres.is_some()
        || set.openvpn.is_some()
        || set.rdp.is_some()
        || set.xmpp.is_some()
        || set.regexp.is_some()
        || set
            .not
            .as_ref()
            .map(|n| n.iter().any(requires_payload_data))
            .unwrap_or(false)
}

fn matches_tls(tls: &Layer4TlsMatcher, ctx: &mut ConnectionContext, buf: &[u8]) -> bool {
    // If not already parsed, parse ClientHello
    if ctx.sni.is_none() && ctx.alpn.is_none() {
        if let Some((sni, alpns)) = parse_tls_client_hello(buf) {
            ctx.sni = sni;
            ctx.alpn = alpns.first().cloned();
        } else if buf.len() < 5 || buf[0] != 0x16 {
            return false;
        }
    }

    // Check SNI
    if !tls.sni.is_empty() {
        let sni = match ctx.sni.as_deref() {
            Some(s) => s,
            None => return false,
        };
        let matches_any = tls.sni.iter().any(|pattern| sni_matches(sni, pattern));
        if !matches_any {
            return false;
        }
    }

    // Check ALPN
    if !tls.alpn.is_empty() {
        let alpn = match ctx.alpn.as_deref() {
            Some(a) => a,
            None => return false,
        };
        let matches_any = tls.alpn.iter().any(|p| p.eq_ignore_ascii_case(alpn));
        if !matches_any {
            return false;
        }
    }

    // If both empty, matching any TLS handshake
    buf.len() >= 5 && buf[0] == 0x16
}

fn sni_matches(sni: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern.starts_with("*.") {
        let suffix = &pattern[1..];
        sni.ends_with(suffix)
    } else {
        sni.eq_ignore_ascii_case(pattern)
    }
}

pub fn parse_tls_client_hello(buf: &[u8]) -> Option<(Option<String>, Vec<String>)> {
    if buf.len() < 43 {
        return None;
    }

    // Record header
    if buf[0] != 0x16 {
        return None;
    }

    // Handshake header: type 0x01 = ClientHello
    if buf[5] != 0x01 {
        return None;
    }

    let mut pos = 43; // skip record header (5) + handshake type (1) + length (3) + version (2) + random (32)

    // Session ID
    if buf.len() <= pos {
        return None;
    }
    let sess_id_len = buf[pos] as usize;
    pos += 1 + sess_id_len;

    // Cipher Suites
    if buf.len() < pos + 2 {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    // Compression Methods
    if buf.len() < pos + 1 {
        return None;
    }
    let comp_methods_len = buf[pos] as usize;
    pos += 1 + comp_methods_len;

    // Extensions
    if buf.len() < pos + 2 {
        return Some((None, Vec::new()));
    }
    let ext_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;

    let ext_end = (pos + ext_len).min(buf.len());
    let mut parsed_sni = None;
    let mut parsed_alpn = Vec::new();

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_data_len > ext_end {
            break;
        }

        let ext_data = &buf[pos..pos + ext_data_len];
        pos += ext_data_len;

        match ext_type {
            0x0000 => {
                // Server Name Indication (SNI)
                if ext_data.len() > 5 {
                    let mut p = 2; // skip server_name_list_length
                    while p + 3 <= ext_data.len() {
                        let name_type = ext_data[p];
                        let name_len = u16::from_be_bytes([ext_data[p + 1], ext_data[p + 2]]) as usize;
                        p += 3;
                        if name_type == 0 && p + name_len <= ext_data.len() {
                            if let Ok(sni_str) = std::str::from_utf8(&ext_data[p..p + name_len]) {
                                parsed_sni = Some(sni_str.to_string());
                                break;
                            }
                        }
                        p += name_len;
                    }
                }
            }
            0x0010 => {
                // Application-Layer Protocol Negotiation (ALPN)
                if ext_data.len() > 2 {
                    let mut p = 2; // skip alpn_extension_length
                    while p < ext_data.len() {
                        let proto_len = ext_data[p] as usize;
                        p += 1;
                        if p + proto_len <= ext_data.len() {
                            if let Ok(proto) = std::str::from_utf8(&ext_data[p..p + proto_len]) {
                                parsed_alpn.push(proto.to_string());
                            }
                        }
                        p += proto_len;
                    }
                }
            }
            _ => {}
        }
    }

    Some((parsed_sni, parsed_alpn))
}

fn matches_http(http: &Layer4HttpMatcher, buf: &[u8]) -> bool {
    if buf.is_empty() {
        return false;
    }

    let standard_methods = [
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "CONNECT ", "PATCH ", "TRACE ",
        "HTTP/",
    ];

    if !http.methods.is_empty() {
        return http.methods.iter().any(|m| {
            let m_upper = m.to_ascii_uppercase();
            let prefix = format!("{} ", m_upper);
            buf.starts_with(prefix.as_bytes())
        });
    }

    standard_methods
        .iter()
        .any(|prefix| buf.starts_with(prefix.as_bytes()))
}

fn matches_ssh(buf: &[u8]) -> bool {
    buf.starts_with(b"SSH-")
}

fn matches_proxy_protocol(buf: &[u8]) -> bool {
    // PROXY v1: "PROXY ..."
    if buf.starts_with(b"PROXY ") {
        return true;
    }
    // PROXY v2: 12-byte header \x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A
    let v2_sig = b"\r\n\r\n\x00\r\nQUIT\n";
    buf.starts_with(v2_sig)
}

fn matches_ip(ranges: &[String], client_ip: IpAddr) -> bool {
    if ranges.is_empty() {
        return true;
    }

    for r in ranges {
        let r_trimmed = r.trim();
        if r_trimmed == "private" {
            if is_private_ip(client_ip) {
                return true;
            }
            continue;
        }

        if let Ok(net) = IpNet::from_str(r_trimmed) {
            if net.contains(&client_ip) {
                return true;
            }
        } else if let Ok(ip) = IpAddr::from_str(r_trimmed) {
            if ip == client_ip {
                return true;
            }
        }
    }

    false
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

fn matches_quic(buf: &[u8]) -> bool {
    // QUIC Long Header packet has first byte bit 7 (0x80) set and bit 6 (0x40) set
    if buf.len() < 5 {
        return false;
    }
    (buf[0] & 0xc0) == 0xc0
}

fn matches_wireguard(buf: &[u8]) -> bool {
    // WireGuard handshake initiation packet: type 0x01 followed by 3 zeroes
    if buf.len() < 4 {
        return false;
    }
    buf[0] == 0x01 && buf[1] == 0x00 && buf[2] == 0x00 && buf[3] == 0x00
}

fn matches_socks4(buf: &[u8]) -> bool {
    if buf.len() < 2 {
        return false;
    }
    buf[0] == 0x04 && (buf[1] == 0x01 || buf[1] == 0x02)
}

fn matches_socks5(buf: &[u8]) -> bool {
    if buf.len() < 2 {
        return false;
    }
    buf[0] == 0x05
}

fn matches_postgres(buf: &[u8]) -> bool {
    if buf.len() < 8 {
        return false;
    }
    // SSLRequest: 80877103 = 0x04, 0xd2, 0x16, 0x2f
    let ssl_req = [0x04, 0xd2, 0x16, 0x2f];
    // Protocol 3.0: 0x00, 0x03, 0x00, 0x00
    let proto_3 = [0x00, 0x03, 0x00, 0x00];

    buf[4..8] == ssl_req || buf[4..8] == proto_3
}

fn matches_openvpn(buf: &[u8]) -> bool {
    if buf.len() < 2 {
        return false;
    }
    // OpenVPN control packet opcode: (opcode << 3) | key_id
    let opcode = (buf[0] >> 3) & 0x1f;
    opcode >= 1 && opcode <= 8
}

fn matches_rdp(buf: &[u8]) -> bool {
    // TPKT header starts with 0x03, 0x00
    buf.len() >= 4 && buf[0] == 0x03 && buf[1] == 0x00
}

fn matches_xmpp(buf: &[u8]) -> bool {
    let s = String::from_utf8_lossy(buf);
    s.contains("<stream:stream") || s.contains("xmlns='jabber:client'")
}
