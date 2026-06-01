// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Minimal hand-rolled SOCKS5 CONNECT client (RFC 1928 + RFC 1929
//! username/password auth) for the C-Tor `ForegroundService`'s SOCKS
//! proxy per D0025 §2 (re-anchored under D0020 §2).
//!
//! Pure-safe-Rust over `tokio`; no third-party SOCKS dependency
//! (D0025 §10 revised 2026-05-31 — the protocol is small enough to own,
//! and we need explicit username/password control for `IsolateSOCKSAuth`).
//!
//! ## Scope + privacy properties
//!
//! Only the `CONNECT` command with a **domain-name** target (`ATYP =
//! 0x03`) is implemented, so hostnames and `.onion` addresses resolve
//! THROUGH Tor at the proxy — never locally (a local DNS leak would
//! defeat the point). The username/password carry the per-conversation
//! `IsolateSOCKSAuth` credential (D0020 §2.6); C-Tor performs the actual
//! circuit isolation. The credential is `hex(SHA-256(conversation_id))`
//! so the (possibly sensitive) `conversation_id` never reaches the
//! proxy's SOCKS-auth log.

// `clippy::redundant_pub_crate` and the workspace's `unreachable_pub`
// (rust) lint are mutually exclusive for items that are crate-visible-
// but-not-public: this module's items are used by `transport.rs` (so they
// cannot be plain-private) but are not public API (so they cannot be
// `pub` without tripping `unreachable_pub`). `pub(crate)` is the correct
// spelling; allow the clippy lint that disagrees.
#![allow(clippy::redundant_pub_crate)]

use std::net::SocketAddr;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

/// SOCKS protocol version (RFC 1928).
const SOCKS5_VERSION: u8 = 0x05;
/// Username/password auth method (RFC 1929).
const AUTH_USERPASS: u8 = 0x02;
/// RFC 1929 sub-negotiation version.
const USERPASS_VERSION: u8 = 0x01;
/// RFC 1929 success status.
const USERPASS_SUCCESS: u8 = 0x00;
/// CONNECT command (RFC 1928).
const CMD_CONNECT: u8 = 0x01;
/// Reserved byte (RFC 1928).
const RSV: u8 = 0x00;
/// Address type: IPv4 (RFC 1928) — only seen in the bound-address reply.
const ATYP_IPV4: u8 = 0x01;
/// Address type: domain name (RFC 1928) — used for the request target so
/// resolution happens at the proxy (over Tor).
const ATYP_DOMAIN: u8 = 0x03;
/// Address type: IPv6 (RFC 1928) — only seen in the bound-address reply.
const ATYP_IPV6: u8 = 0x04;
/// CONNECT reply: succeeded.
const REP_SUCCEEDED: u8 = 0x00;
/// CONNECT reply: host unreachable.
const REP_HOST_UNREACHABLE: u8 = 0x04;
/// CONNECT reply: connection refused.
const REP_CONNECTION_REFUSED: u8 = 0x05;

/// Internal SOCKS5 client failure. The caller (`transport.rs`) maps these
/// onto [`crate::error::TorTransportError`]: [`Self::Transport`] is
/// retryable (a loopback transport failure); the rest are terminal.
#[derive(Debug)]
pub(crate) enum Socks5Error {
    /// Loopback connect/read/write failure — retryable within the budget.
    Transport,
    /// The proxy did not select username/password auth.
    AuthMethodRejected,
    /// RFC 1929 auth returned a non-success status.
    AuthFailed,
    /// CONNECT reply `0x04`: the target did not resolve/route over Tor.
    HostUnreachable,
    /// CONNECT reply `0x05`: the target refused the connection.
    ConnectionRefused,
    /// Any other CONNECT reply code, or malformed/short framing.
    Protocol,
    /// `target_host` (or the credential) exceeds the 255-byte SOCKS field.
    TargetHostTooLong,
}

/// The per-conversation `IsolateSOCKSAuth` credential per D0020 §2.6:
/// `hex(SHA-256(conversation_id))`.
pub(crate) fn isolation_credential(conversation_id: &[u8]) -> String {
    use core::fmt::Write as _;
    let digest = Sha256::digest(conversation_id);
    let mut s = String::with_capacity(64);
    for b in digest {
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

/// Open a SOCKS5 CONNECT tunnel to `(target_host, target_port)` through
/// the proxy at `proxy_addr`, authenticating with `credential` as BOTH
/// the username and the password (so C-Tor isolates the circuit by the
/// pair). Returns the tunneled [`TcpStream`] positioned at the payload.
pub(crate) async fn connect_through_proxy(
    proxy_addr: SocketAddr,
    credential: &str,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, Socks5Error> {
    let host = target_host.as_bytes();
    let host_len = u8::try_from(host.len()).map_err(|_| Socks5Error::TargetHostTooLong)?;
    let cred = credential.as_bytes();
    let cred_len = u8::try_from(cred.len()).map_err(|_| Socks5Error::TargetHostTooLong)?;

    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .map_err(|_| Socks5Error::Transport)?;

    // (1) Method negotiation: offer ONLY username/password so the proxy
    // must use the per-conversation isolation credential.
    stream
        .write_all(&[SOCKS5_VERSION, 0x01, AUTH_USERPASS])
        .await
        .map_err(|_| Socks5Error::Transport)?;
    let mut sel = [0u8; 2];
    stream
        .read_exact(&mut sel)
        .await
        .map_err(|_| Socks5Error::Transport)?;
    let [sel_ver, sel_method] = sel;
    if sel_ver != SOCKS5_VERSION {
        return Err(Socks5Error::Protocol);
    }
    if sel_method != AUTH_USERPASS {
        return Err(Socks5Error::AuthMethodRejected);
    }

    // (2) RFC 1929 username/password sub-negotiation.
    let mut auth = Vec::with_capacity(cred.len().saturating_mul(2).saturating_add(3));
    auth.push(USERPASS_VERSION);
    auth.push(cred_len);
    auth.extend_from_slice(cred);
    auth.push(cred_len);
    auth.extend_from_slice(cred);
    stream
        .write_all(&auth)
        .await
        .map_err(|_| Socks5Error::Transport)?;
    let mut auth_reply = [0u8; 2];
    stream
        .read_exact(&mut auth_reply)
        .await
        .map_err(|_| Socks5Error::Transport)?;
    let [_auth_ver, auth_status] = auth_reply;
    if auth_status != USERPASS_SUCCESS {
        return Err(Socks5Error::AuthFailed);
    }

    // (3) CONNECT with a domain-name target — resolution at the proxy
    // (over Tor), never locally.
    let mut req = Vec::with_capacity(host.len().saturating_add(7));
    req.push(SOCKS5_VERSION);
    req.push(CMD_CONNECT);
    req.push(RSV);
    req.push(ATYP_DOMAIN);
    req.push(host_len);
    req.extend_from_slice(host);
    req.extend_from_slice(&target_port.to_be_bytes());
    stream
        .write_all(&req)
        .await
        .map_err(|_| Socks5Error::Transport)?;

    // (4) Reply: VER REP RSV ATYP BND.ADDR BND.PORT.
    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|_| Socks5Error::Transport)?;
    let [rep_ver, rep_code, _rep_rsv, rep_atyp] = head;
    if rep_ver != SOCKS5_VERSION {
        return Err(Socks5Error::Protocol);
    }
    match rep_code {
        REP_SUCCEEDED => {}
        REP_HOST_UNREACHABLE => return Err(Socks5Error::HostUnreachable),
        REP_CONNECTION_REFUSED => return Err(Socks5Error::ConnectionRefused),
        _ => return Err(Socks5Error::Protocol),
    }

    // Drain BND.ADDR + BND.PORT so the returned stream is positioned at
    // the start of the tunneled payload.
    let addr_len = match rep_atyp {
        ATYP_IPV4 => 4usize,
        ATYP_IPV6 => 16usize,
        ATYP_DOMAIN => {
            let mut dlen = [0u8; 1];
            stream
                .read_exact(&mut dlen)
                .await
                .map_err(|_| Socks5Error::Transport)?;
            let [d] = dlen;
            usize::from(d)
        }
        _ => return Err(Socks5Error::Protocol),
    };
    let mut scratch = vec![0u8; addr_len.saturating_add(2)];
    stream
        .read_exact(&mut scratch)
        .await
        .map_err(|_| Socks5Error::Transport)?;

    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::isolation_credential;

    #[test]
    fn isolation_credential_is_deterministic_64_lowercase_hex() {
        let a = isolation_credential(b"conversation-1");
        let b = isolation_credential(b"conversation-1");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert!(
            a.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn isolation_credential_distinct_for_distinct_conversations() {
        assert_ne!(
            isolation_credential(b"conversation-a"),
            isolation_credential(b"conversation-b")
        );
    }
}
