// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! The simplex-chat command/response/event JSON layer (D0026 §1.3).
//!
//! This is the "Cairn owns the command/JSON layer" cost of the lean
//! `simploxide-ws-core` dependency (D0026 §12): rather than the high-level
//! `simploxide-client` Bot SDK, the adapter speaks the simplex-chat
//! WebSocket API directly — string commands in, tagged-JSON responses and
//! events out (`simploxide_ws_core::RawClient::send` returns the response
//! `String`; the `EventQueue` yields unsolicited event `String`s).
//!
//! ## What is and isn't verified here
//!
//! - **Command strings** are reference-derived from the published
//!   simplex-chat WS API (the `simploxide-api-types` 0.9.0 `CommandSyntax`
//!   renderings): create-invitation = `/_connect <userId>`, connect-via-link
//!   = `/_connect <userId> <link>`, file-send = `/_send <chatRef> json
//!   <composedMessages>`, file-receive = `/freceive <fileId>`.
//! - **Response / event parsing** is intentionally **defensive**: it pulls
//!   the `resp` / event object, reads its `type` tag, and extracts the few
//!   fields Cairn needs, tolerating the surrounding shape. No simplex-chat
//!   type is mirrored as a rigid Rust struct (that is exactly the
//!   `api-types` trust-surface this path sheds).
//! - **Wire fidelity to a specific simplex-chat version** — the exact `type`
//!   tags, the `CryptoFile` `fileSource` shape, and the received-file event
//!   sequence — is validated **only** under the `integration-tests` feature
//!   against a live SimpleX Chat CLI (D0026 §12). The unit tests below prove
//!   the builders + parsers are internally consistent against
//!   reference-shaped fixtures; they are NOT a claim of live-daemon
//!   correctness.
//!
//! All functions are pure (`&str` / `&Value` in, owned out) so they unit-test
//! without any network — the network plumbing lives in
//! [`crate::sidecar`].

// The builders/parsers are `pub(crate)` so the sibling `sidecar` module can
// call them. clippy's `redundant_pub_crate` (nursery) would have us drop to
// `pub` since this module is crate-private — but bare `pub` here trips the
// workspace `unreachable_pub` lint (these are not public API). The two lints
// conflict for cross-sibling internal items; `pub(crate)` is the correct
// spelling, so the nursery lint is allowed for this internal module.
#![allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) needed for the sibling sidecar module; `pub` would trip unreachable_pub"
)]

use serde_json::Value;

/// A parsed simplex-chat response/event: the inner object + its `type` tag.
///
/// The same simplex-chat core wraps its replies differently per transport
/// (D0026 §12 FFI host-runtime finding, 2026-06-01):
/// - **ws-core / CLI-WebSocket:** `{"corrId": "..", "resp": {"type": ..}}`
///   for command responses, `{"resp": {"type": ..}}` (no `corrId`) for events.
///   `simploxide-ws-core` splits the two by `corrId` (its dispatcher routes
///   responses to the awaiting `send` future and events to the queue).
/// - **FFI / in-process `libsimplex`** (`simploxide-ffi-core`, Android):
///   `{"result": {"type": ..}}` for BOTH responses and events (no `corrId`).
///   Verified empirically against in-process `libsimplex` v6.5.3.0.
///
/// The outer envelope key differs (`resp` vs `result`) but the inner
/// `{"type": .., ..}` object is identical, so [`Self::from_frame`] accepts
/// either key and every downstream parser is transport-agnostic — the
/// [`crate::sidecar`] FFI + ws-core transports share one protocol layer.
pub(crate) struct Resp<'a> {
    /// The `type` discriminator of the inner object (e.g. `"newChatItems"`,
    /// `"activeUser"`, `"chatCmdError"`).
    pub(crate) tag: &'a str,
    /// The inner `resp` / `result` object itself, for field extraction.
    pub(crate) body: &'a Value,
}

impl<'a> Resp<'a> {
    /// Reach into a parsed frame's inner object (`resp` for ws-core/CLI,
    /// `result` for the FFI/in-process transport) + read its `type` tag.
    ///
    /// Returns `None` if there is neither a `resp` nor a `result` object, or
    /// it lacks a string `type` — both of which a caller treats as a protocol
    /// error.
    pub(crate) fn from_frame(frame: &'a Value) -> Option<Self> {
        // ws-core/CLI uses `resp`; FFI in-process uses `result` (D0026 §12).
        // Both carry the same inner `{"type": ..}` object.
        let body = frame.get("resp").or_else(|| frame.get("result"))?;
        let tag = body.get("type")?.as_str()?;
        Some(Self { tag, body })
    }

    /// `true` if this `resp` is a simplex-chat command error
    /// (`chatCmdError` / `chatError` / `error`), which Cairn surfaces as a
    /// [`crate::error::SimplexAdapterError::SidecarProtocol`].
    pub(crate) fn is_error(&self) -> bool {
        matches!(self.tag, "chatCmdError" | "chatError" | "error")
    }
}

/// Parse a raw simplex-chat frame string into a JSON value.
pub(crate) fn parse_frame(raw: &str) -> Option<Value> {
    serde_json::from_str(raw).ok()
}

// ===================================================================
// Command builders (reference-derived simplex-chat WS API strings)
// ===================================================================

/// `/user` — show the active user. Cairn issues this once on connect to
/// learn the `userId` the `/_connect` / `/_send` commands require.
pub(crate) fn cmd_show_active_user() -> String {
    "/user".to_string()
}

/// `/_connect <userId>` — create a new one-time invitation queue
/// (`ApiAddContact`). The response carries the invitation link.
pub(crate) fn cmd_create_invitation(user_id: i64) -> String {
    format!("/_connect {user_id}")
}

/// `/_connect <userId> <link>` — connect via a peer's prepared invitation
/// link (`ApiConnect`). The response confirms the connection was initiated.
pub(crate) fn cmd_connect_via_link(user_id: i64, link: &str) -> String {
    format!("/_connect {user_id} {link}")
}

/// `/_send <chatRef> json <composedMessages>` — send one message. Cairn's
/// carrier is a binary `CryptoFile` (D0026 §2.4 carrier decision), so the
/// composed message is a single file item whose content is the envelope
/// bytes already written to `file_path` by the caller.
///
/// `chat_ref` is the direct-contact reference `@<contactId>` (the
/// `ConnectionId` the sidecar assigned at pairing).
pub(crate) fn cmd_send_file(chat_ref: &str, file_path: &str) -> String {
    // A single composed message: an empty-text file item pointing at the
    // on-disk envelope. simplex-chat reads the file, XFTP-encrypts +
    // uploads it. `text` is empty — Cairn's payload is the file content,
    // never a visible message body.
    let composed = Value::Array(vec![serde_json::json!({
        "msgContent": { "type": "file", "text": "" },
        "fileSource": { "filePath": file_path }
    })]);
    format!("/_send {chat_ref} json {composed}")
}

/// `/freceive <fileId>` — accept an offered incoming file so the sidecar
/// XFTP-downloads it. Issued when a received-file offer event arrives;
/// completion then surfaces as a separate event carrying the local path.
pub(crate) fn cmd_receive_file(file_id: i64) -> String {
    format!("/freceive {file_id}")
}

// ===================================================================
// Response parsers (defensive field extraction)
// ===================================================================

/// Extract the active `userId` from a `/user` response (`activeUser` →
/// `user.userId`).
pub(crate) fn parse_active_user_id(resp: &Resp<'_>) -> Option<i64> {
    resp.body.get("user")?.get("userId")?.as_i64()
}

/// Extract the invitation link from a create-invitation response. The
/// reference field is `connLinkInvitation`; older shapes used
/// `connReqInvitation`. We accept either and pull the connection-link
/// string (which itself may be nested under `connFullLink` / be a bare
/// string), tolerating the surrounding shape.
pub(crate) fn parse_invitation_link(resp: &Resp<'_>) -> Option<String> {
    let link = resp
        .body
        .get("connLinkInvitation")
        .or_else(|| resp.body.get("connReqInvitation"))?;
    extract_conn_link(link)
}

/// Extract the established `contactId` from a `contactConnected` event — the
/// reference Cairn keys the connection by and uses for `/_send @<contactId>`.
///
/// LIVE-VALIDATION FINDING (D0026 §12, 2026-06-01): a create/accept response
/// carries only a *pending* `connection.pccConnId`, which is NOT usable for
/// sending; the usable `contactId` arrives later with the async
/// `contactConnected` event (`contact.contactId`). The transport therefore
/// awaits this event before yielding a `ConnectionId`.
pub(crate) fn parse_contact_connected(resp: &Resp<'_>) -> Option<i64> {
    if resp.tag != "contactConnected" {
        return None;
    }
    resp.body.get("contact")?.get("contactId")?.as_i64()
}

/// A received-file offer parsed from an incoming event: the `fileId` to
/// accept so the sidecar XFTP-downloads it, plus the `contactId` of the
/// conversation it belongs to (for per-connection recv demultiplexing,
/// D0026 §12).
pub(crate) struct ReceivedFileOffer {
    /// The simplex-chat file id to pass to [`cmd_receive_file`].
    pub(crate) file_id: i64,
    /// The `chatInfo.contact.contactId` the offer arrived on, if present —
    /// the [`crate::adapter::ConnectionId`] the recv path routes by. `None`
    /// when the offer's `chatInfo` is not a direct contact (e.g. a group, a
    /// shape Cairn's v1 1:1 model does not use).
    pub(crate) contact_id: Option<i64>,
}

/// Detect an incoming-file offer in a `newChatItems` event + pull the
/// `fileId` to accept. Returns `None` for events that are not a received
/// file (text messages, status updates, etc.).
///
/// The offer's `fileId` + its `chatInfo.contact.contactId` (the recv path
/// uses the latter to demultiplex by connection, D0026 §12).
pub(crate) fn parse_received_file_offer(resp: &Resp<'_>) -> Option<ReceivedFileOffer> {
    if resp.tag != "newChatItems" {
        return None;
    }
    let items = resp.body.get("chatItems")?.as_array()?;
    let first = items.first()?;
    let chat_item = first.get("chatItem")?;
    let file_id = chat_item.get("file")?.get("fileId")?.as_i64()?;
    // The conversation the offer belongs to. Direct-contact shape:
    // `chatInfo.contact.contactId`. Absent / non-contact → `None` (the recv
    // loop then treats it as the single active conversation, the v1 default).
    let contact_id = first
        .get("chatInfo")
        .and_then(|ci| ci.get("contact"))
        .and_then(|c| c.get("contactId"))
        .and_then(Value::as_i64);
    Some(ReceivedFileOffer {
        file_id,
        contact_id,
    })
}

/// The `fileId` the daemon assigned to an OUTGOING file send, parsed from the
/// `/_send` `newChatItems` response. [`crate::sidecar`] awaits the matching
/// `sndFileCompleteXFTP` event (below) before reporting the send done —
/// delivery assurance, not fire-and-forget (D0026 §12).
pub(crate) fn parse_sent_file_id(resp: &Resp<'_>) -> Option<i64> {
    if resp.tag != "newChatItems" {
        return None;
    }
    resp.body
        .get("chatItems")?
        .as_array()?
        .first()?
        .get("chatItem")?
        .get("file")?
        .get("fileId")?
        .as_i64()
}

/// Detect the send-side XFTP **upload completion** event
/// (`sndFileCompleteXFTP`) + pull its `fileId`, so the send path can confirm
/// the envelope actually reached the XFTP relay (vs. merely being queued).
/// `sndFileProgressXFTP` + unrelated events return `None` (keep waiting).
pub(crate) fn parse_snd_file_complete(resp: &Resp<'_>) -> Option<i64> {
    if resp.tag != "sndFileCompleteXFTP" {
        return None;
    }
    // Reference-derived (live-gated, D0026 §12): the fileId surfaces under the
    // chat item's file record or the transfer meta, depending on shape.
    resp.body
        .get("chatItem")
        .and_then(|ci| ci.get("file"))
        .and_then(|f| f.get("fileId"))
        .and_then(Value::as_i64)
        .or_else(|| {
            resp.body
                .get("fileTransferMeta")
                .and_then(|m| m.get("fileId"))
                .and_then(Value::as_i64)
        })
        .or_else(|| resp.body.get("fileId").and_then(Value::as_i64))
}

/// A received-file *completion* (`rcvFileComplete`): the local path the
/// sidecar wrote the decrypted file to (Cairn reads it back as the envelope
/// bytes), plus the `fileId` so the recv path can route the completion to the
/// connection whose offer it accepted (D0026 §12).
pub(crate) struct RcvFileComplete {
    /// The completed transfer's `fileId`, if present — matched against the
    /// offer's `fileId` to recover the owning connection.
    pub(crate) file_id: Option<i64>,
    /// The local filesystem path of the decrypted file.
    pub(crate) path: String,
}

/// Detect a received-file completion event + pull its path + `fileId`.
pub(crate) fn parse_rcv_file_complete(resp: &Resp<'_>) -> Option<RcvFileComplete> {
    if resp.tag != "rcvFileComplete" {
        return None;
    }
    // The completed file's local path lives under the chat item's file
    // record (`fileSource.filePath`, older shapes: `filePath`).
    let file = resp
        .body
        .get("chatItem")
        .and_then(|ci| ci.get("chatItem"))
        .and_then(|ci| ci.get("file"))
        .or_else(|| resp.body.get("rcvFileTransfer"))?;
    let path = file
        .get("fileSource")
        .and_then(|fs| fs.get("filePath"))
        .or_else(|| file.get("filePath"))
        .and_then(Value::as_str)
        .map(ToString::to_string)?;
    let file_id = file.get("fileId").and_then(Value::as_i64);
    Some(RcvFileComplete { file_id, path })
}

// ===================================================================
// Small helpers
// ===================================================================

/// Pull a connection-link string out of a `connLinkInvitation`-style value,
/// which may be a bare string or an object with a `connFullLink` /
/// `connLinkContact` field.
fn extract_conn_link(value: &Value) -> Option<String> {
    if let Some(s) = value.as_str() {
        return Some(s.to_string());
    }
    value
        .get("connFullLink")
        .or_else(|| value.get("connLinkContact"))
        .or_else(|| value.get("cReqInvitation"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests assert on known-shape fixtures; index/unwrap panics ARE the failure signal"
)]
mod tests {
    use super::*;

    #[test]
    fn command_strings_match_reference_syntax() {
        assert_eq!(cmd_show_active_user(), "/user");
        assert_eq!(cmd_create_invitation(1), "/_connect 1");
        assert_eq!(
            cmd_connect_via_link(1, "simplex:/invitation#abc"),
            "/_connect 1 simplex:/invitation#abc"
        );
        assert_eq!(cmd_receive_file(42), "/freceive 42");
    }

    #[test]
    fn send_file_command_carries_empty_text_file_item() {
        let cmd = cmd_send_file("@7", "/tmp/cairn/env.bin");
        // `/_send <chatRef> json <array>` shape, with a file item whose text
        // is empty (Cairn's payload is the file content, never a body).
        assert!(cmd.starts_with("/_send @7 json "));
        let json_part = cmd.strip_prefix("/_send @7 json ").unwrap();
        let parsed: Value = serde_json::from_str(json_part).unwrap();
        let item = &parsed.as_array().unwrap()[0];
        assert_eq!(item["msgContent"]["type"], "file");
        assert_eq!(item["msgContent"]["text"], "");
        assert_eq!(item["fileSource"]["filePath"], "/tmp/cairn/env.bin");
    }

    #[test]
    fn parses_active_user_id() {
        let frame =
            parse_frame(r#"{"corrId":"1","resp":{"type":"activeUser","user":{"userId":5}}}"#)
                .unwrap();
        let resp = Resp::from_frame(&frame).unwrap();
        assert_eq!(resp.tag, "activeUser");
        assert_eq!(parse_active_user_id(&resp), Some(5));
    }

    #[test]
    fn parses_ffi_result_envelope() {
        // The Android in-process FFI transport (simploxide-ffi-core) wraps
        // replies as `{"result": {...}}` rather than the ws-core/CLI
        // `{"resp": {...}}` — verified against in-process libsimplex v6.5.3.0
        // (D0026 §12 FFI host-runtime proof). Resp::from_frame must accept it
        // so the FFI + ws-core transports share one protocol layer. These
        // fixtures are the EXACT shapes the host runtime proof observed.
        let user = parse_frame(
            r#"{"result":{"type":"activeUser","user":{"userId":1,"localDisplayName":"cairn"}}}"#,
        )
        .unwrap();
        let resp = Resp::from_frame(&user).unwrap();
        assert_eq!(resp.tag, "activeUser");
        assert_eq!(parse_active_user_id(&resp), Some(1));

        let inv = parse_frame(
            r#"{"result":{"type":"invitation","connLinkInvitation":{"connFullLink":"simplex:/invitation#/?v=2-7"}}}"#,
        )
        .unwrap();
        assert_eq!(
            parse_invitation_link(&Resp::from_frame(&inv).unwrap()).as_deref(),
            Some("simplex:/invitation#/?v=2-7")
        );

        // The `resp` envelope still takes precedence + works (ws-core path).
        let ws = parse_frame(r#"{"corrId":"1","resp":{"type":"activeUser","user":{"userId":9}}}"#)
            .unwrap();
        assert_eq!(
            parse_active_user_id(&Resp::from_frame(&ws).unwrap()),
            Some(9)
        );
    }

    #[test]
    fn parses_invitation_link_bare_and_nested() {
        let bare = parse_frame(
            r#"{"resp":{"type":"invitation","connLinkInvitation":"simplex:/invitation#xyz"}}"#,
        )
        .unwrap();
        assert_eq!(
            parse_invitation_link(&Resp::from_frame(&bare).unwrap()).as_deref(),
            Some("simplex:/invitation#xyz")
        );
        let nested = parse_frame(
            r#"{"resp":{"type":"invitation","connLinkInvitation":{"connFullLink":"simplex:/inv#n"}}}"#,
        )
        .unwrap();
        assert_eq!(
            parse_invitation_link(&Resp::from_frame(&nested).unwrap()).as_deref(),
            Some("simplex:/inv#n")
        );
    }

    #[test]
    fn parses_contact_connected_contact_id() {
        let frame =
            parse_frame(r#"{"resp":{"type":"contactConnected","contact":{"contactId":4}}}"#)
                .unwrap();
        assert_eq!(
            parse_contact_connected(&Resp::from_frame(&frame).unwrap()),
            Some(4)
        );
        // A non-contactConnected event (e.g. the earlier contactConnecting
        // phase) yields None.
        let other = parse_frame(r#"{"resp":{"type":"contactConnecting"}}"#).unwrap();
        assert_eq!(
            parse_contact_connected(&Resp::from_frame(&other).unwrap()),
            None
        );
    }

    #[test]
    fn detects_received_file_offer_and_completion() {
        let offer = parse_frame(
            r#"{"resp":{"type":"newChatItems","chatItems":[{"chatInfo":{"contact":{"contactId":7}},"chatItem":{"file":{"fileId":99}}}]}}"#,
        )
        .unwrap();
        let parsed = parse_received_file_offer(&Resp::from_frame(&offer).unwrap()).unwrap();
        assert_eq!(parsed.file_id, 99);
        // The offer carries its conversation's contactId for recv demux.
        assert_eq!(parsed.contact_id, Some(7));

        let complete = parse_frame(
            r#"{"resp":{"type":"rcvFileComplete","chatItem":{"chatItem":{"file":{"fileId":99,"fileSource":{"filePath":"/var/cairn/in.bin"}}}}}}"#,
        )
        .unwrap();
        let done = parse_rcv_file_complete(&Resp::from_frame(&complete).unwrap()).unwrap();
        assert_eq!(done.path, "/var/cairn/in.bin");
        // The completion carries its fileId so recv can route it to the
        // connection whose offer (fileId 99) it accepted.
        assert_eq!(done.file_id, Some(99));
    }

    #[test]
    fn detects_sent_file_id_and_snd_complete() {
        // The `/_send` newChatItems response carries the assigned fileId; the
        // send path awaits the matching sndFileCompleteXFTP (delivery
        // assurance, D0026 §12).
        let sent = parse_frame(
            r#"{"resp":{"type":"newChatItems","chatItems":[{"chatItem":{"file":{"fileId":5}}}]}}"#,
        )
        .unwrap();
        assert_eq!(
            parse_sent_file_id(&Resp::from_frame(&sent).unwrap()),
            Some(5)
        );

        let done = parse_frame(
            r#"{"resp":{"type":"sndFileCompleteXFTP","chatItem":{"file":{"fileId":5}}}}"#,
        )
        .unwrap();
        assert_eq!(
            parse_snd_file_complete(&Resp::from_frame(&done).unwrap()),
            Some(5)
        );
        // The progress event is NOT the completion → None (keep waiting).
        let progress =
            parse_frame(r#"{"resp":{"type":"sndFileProgressXFTP","sentSize":10}}"#).unwrap();
        assert_eq!(
            parse_snd_file_complete(&Resp::from_frame(&progress).unwrap()),
            None
        );
    }

    #[test]
    fn non_file_event_is_not_a_file_offer() {
        let text_msg = parse_frame(
            r#"{"resp":{"type":"newChatItems","chatItems":[{"chatItem":{"content":{"type":"rcvMsgContent"}}}]}}"#,
        )
        .unwrap();
        assert!(parse_received_file_offer(&Resp::from_frame(&text_msg).unwrap()).is_none());
    }

    #[test]
    fn detects_command_error_resp() {
        let err =
            parse_frame(r#"{"corrId":"3","resp":{"type":"chatCmdError","chatError":{}}}"#).unwrap();
        assert!(Resp::from_frame(&err).unwrap().is_error());
    }
}
