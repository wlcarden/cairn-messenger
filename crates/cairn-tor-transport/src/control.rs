// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Minimal hand-rolled Tor control-port client (SAFECOOKIE auth) for the
//! C-Tor `ForegroundService` per D0025 §1.1 / §4 (re-anchored under
//! D0020 §2).
//!
//! Pure-safe-Rust over `tokio`. Per-command lifecycle (D0025 §5.2): each
//! call opens a fresh control connection, authenticates, runs ONE command,
//! and closes — stateless + individually cancel-safe. NEWNYM and
//! bootstrap-status are infrequent, so re-authenticating per command is
//! cheap and avoids any held-connection reconnect state.
//!
//! ## SAFECOOKIE (Tor control-spec)
//!
//! Authentication uses SAFECOOKIE (challenge-response) rather than plain
//! `COOKIE`, so the 32-byte cookie is never transmitted on the wire:
//!
//! 1. read the 32-byte cookie file (path supplied by the Android shell,
//!    which controls the C-Tor data dir);
//! 2. `AUTHCHALLENGE SAFECOOKIE <hex(client_nonce)>`;
//! 3. verify the server's `SERVERHASH = HMAC(server_key, cookie ‖
//!    client_nonce ‖ server_nonce)` in constant time;
//! 4. `AUTHENTICATE <hex(HMAC(client_key, cookie ‖ client_nonce ‖
//!    server_nonce))>`.
//!
//! The HMAC-SHA256 is computed as HKDF-Extract (`HKDF-Extract(salt, IKM)
//! == HMAC-Hash(salt, IKM)`) via the already-pinned `hkdf` crate — an
//! audited primitive, no hand-rolled crypto, no new dependency pin.

// See socks5.rs: `pub(crate)` items in this private module are used by
// transport.rs but are not public API; `redundant_pub_crate` and
// `unreachable_pub` are mutually exclusive for that visibility class.
#![allow(clippy::redundant_pub_crate)]

use std::net::SocketAddr;
use std::path::Path;

use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use tokio::io::{AsyncBufRead, AsyncBufReadExt as _, AsyncWrite, AsyncWriteExt as _, BufReader};
use tokio::net::TcpStream;

/// Tor SAFECOOKIE cookie length (control-spec).
const COOKIE_LEN: usize = 32;
/// HMAC key for the server-to-controller hash (Tor control-spec).
const SERVER_KEY: &[u8] = b"Tor safe cookie authentication server-to-controller hash";
/// HMAC key for the controller-to-server hash (Tor control-spec).
const CLIENT_KEY: &[u8] = b"Tor safe cookie authentication controller-to-server hash";

/// Internal control-port client failure. The caller (`transport.rs`) maps
/// these onto [`crate::error::TorTransportError`].
#[derive(Debug)]
pub(crate) enum ControlError {
    /// Loopback connect/read/write failure or EOF mid-reply.
    Transport,
    /// The cookie file could not be read or was not 32 bytes.
    CookieRead,
    /// SAFECOOKIE authentication was rejected, or the server's hash did
    /// not verify against the cookie.
    AuthFailed,
    /// Malformed / unexpected control-port reply (non-`250`, short line,
    /// or unparseable `AUTHCHALLENGE`).
    Protocol,
}

/// Compute `HMAC-SHA256(key, msg)` via HKDF-Extract (which IS
/// `HMAC-Hash(salt=key, IKM=msg)`), using the audited `hkdf` crate.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let (prk, _hkdf) = Hkdf::<Sha256>::extract(Some(key), msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    out
}

/// Run a single control-port `command` against `control_addr`, SAFECOOKIE-
/// authenticating with the cookie at `cookie_path`. Returns the reply's
/// content lines (the text after each `250`/`250-` status prefix).
pub(crate) async fn run_command(
    control_addr: SocketAddr,
    cookie_path: &Path,
    command: &str,
) -> Result<Vec<String>, ControlError> {
    let cookie = std::fs::read(cookie_path).map_err(|_| ControlError::CookieRead)?;
    if cookie.len() != COOKIE_LEN {
        return Err(ControlError::CookieRead);
    }

    let mut stream = TcpStream::connect(control_addr)
        .await
        .map_err(|_| ControlError::Transport)?;
    let (read_half, mut write_half) = stream.split();
    let mut reader = BufReader::new(read_half);

    safecookie_authenticate(&mut reader, &mut write_half, &cookie).await?;
    write_line(&mut write_half, command).await?;
    read_reply(&mut reader).await
}

/// Drive the SAFECOOKIE challenge-response.
async fn safecookie_authenticate<R, W>(
    reader: &mut R,
    writer: &mut W,
    cookie: &[u8],
) -> Result<(), ControlError>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut client_nonce = [0u8; 32];
    getrandom::getrandom(&mut client_nonce).map_err(|_| ControlError::Transport)?;

    write_line(
        writer,
        &format!("AUTHCHALLENGE SAFECOOKIE {}", to_hex(&client_nonce)),
    )
    .await?;
    // Any non-250 here (e.g. the server lacks SAFECOOKIE) is an auth failure.
    let reply = read_reply(reader)
        .await
        .map_err(|_| ControlError::AuthFailed)?;
    let line = reply.first().ok_or(ControlError::Protocol)?;
    let (server_hash, server_nonce) = parse_authchallenge(line)?;

    // msg = cookie ‖ client_nonce ‖ server_nonce.
    let mut msg = Vec::with_capacity(cookie.len().saturating_add(64));
    msg.extend_from_slice(cookie);
    msg.extend_from_slice(&client_nonce);
    msg.extend_from_slice(&server_nonce);

    // Verify the server actually holds the cookie (constant-time).
    let expected_server = hmac_sha256(SERVER_KEY, &msg);
    if !bool::from(expected_server.as_slice().ct_eq(server_hash.as_slice())) {
        return Err(ControlError::AuthFailed);
    }

    let client_hash = hmac_sha256(CLIENT_KEY, &msg);
    write_line(writer, &format!("AUTHENTICATE {}", to_hex(&client_hash))).await?;
    read_reply(reader)
        .await
        .map_err(|_| ControlError::AuthFailed)?;
    Ok(())
}

/// Parse `AUTHCHALLENGE SERVERHASH=<64hex> SERVERNONCE=<64hex>` (the
/// content line, with the `250 ` prefix already stripped) into the two
/// 32-byte values.
fn parse_authchallenge(line: &str) -> Result<([u8; 32], [u8; 32]), ControlError> {
    let mut server_hash: Option<[u8; 32]> = None;
    let mut server_nonce: Option<[u8; 32]> = None;
    for token in line.split(' ') {
        if let Some(hex) = token.strip_prefix("SERVERHASH=") {
            server_hash = Some(from_hex_32(hex).ok_or(ControlError::Protocol)?);
        } else if let Some(hex) = token.strip_prefix("SERVERNONCE=") {
            server_nonce = Some(from_hex_32(hex).ok_or(ControlError::Protocol)?);
        }
    }
    Ok((
        server_hash.ok_or(ControlError::Protocol)?,
        server_nonce.ok_or(ControlError::Protocol)?,
    ))
}

/// Write `line` followed by the control-protocol `\r\n` terminator.
async fn write_line<W: AsyncWrite + Unpin>(writer: &mut W, line: &str) -> Result<(), ControlError> {
    writer
        .write_all(line.as_bytes())
        .await
        .map_err(|_| ControlError::Transport)?;
    writer
        .write_all(b"\r\n")
        .await
        .map_err(|_| ControlError::Transport)?;
    Ok(())
}

/// Read one (possibly multi-line) control reply. Returns the content after
/// each line's `<code><sep>` prefix; errors on any non-`250` status, a
/// short line, or EOF mid-reply.
async fn read_reply<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<Vec<String>, ControlError> {
    let mut out = Vec::new();
    loop {
        let mut buf = Vec::new();
        let n = reader
            .read_until(b'\n', &mut buf)
            .await
            .map_err(|_| ControlError::Transport)?;
        if n == 0 {
            return Err(ControlError::Protocol); // EOF mid-reply
        }
        while matches!(buf.last(), Some(b'\n' | b'\r')) {
            buf.pop();
        }
        let line = String::from_utf8(buf).map_err(|_| ControlError::Protocol)?;
        let code = line.get(0..3).ok_or(ControlError::Protocol)?;
        let sep = line
            .as_bytes()
            .get(3)
            .copied()
            .ok_or(ControlError::Protocol)?;
        if code != "250" {
            return Err(ControlError::Protocol);
        }
        out.push(line.get(4..).unwrap_or("").to_string());
        // ' ' marks the final line; '-'/'+' are continuations.
        if sep == b' ' {
            return Ok(out);
        }
    }
}

/// Lowercase-hex-encode a byte slice.
fn to_hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

/// Decode exactly 64 hex chars into a `[u8; 32]`, or `None`.
fn from_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_nibble(*bytes.get(i.saturating_mul(2))?)?;
        let lo = hex_nibble(*bytes.get(i.saturating_mul(2).saturating_add(1))?)?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

const fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(c.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{from_hex_32, hmac_sha256, parse_authchallenge, to_hex};

    #[test]
    fn hmac_sha256_matches_rfc4231_test_case_1() {
        // RFC 4231 §4.2: key = 0x0b * 20, data = "Hi There".
        let key = [0x0bu8; 20];
        let mac = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            to_hex(&mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0xABu8; 32];
        let hex = to_hex(&bytes);
        assert_eq!(hex.len(), 64);
        assert_eq!(from_hex_32(&hex), Some(bytes));
    }

    #[test]
    fn from_hex_32_rejects_wrong_length_and_non_hex() {
        assert_eq!(from_hex_32("abcd"), None);
        assert_eq!(from_hex_32(&"z".repeat(64)), None);
    }

    #[test]
    fn parse_authchallenge_extracts_both_values() {
        let line = format!(
            "AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}",
            "11".repeat(32),
            "22".repeat(32)
        );
        let (hash, nonce) = parse_authchallenge(&line).unwrap();
        assert_eq!(hash, [0x11u8; 32]);
        assert_eq!(nonce, [0x22u8; 32]);
    }
}
