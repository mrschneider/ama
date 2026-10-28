//! Hand-rolled Protocol Buffers encoding for the envelope contract
//! (§3: "protobuf remains an option" — this is that option, with ZERO
//! new dependencies; the schema lives in the kernel's check, not in the
//! encoder, per the project rule).
//!
//! Wire format: [0x0A magic][u32 LE total length][protobuf message].
//! The 0x0A magic is not arbitrary: it IS the protobuf tag of field 1
//! (`kind`, a string) — the first field of every envelope — so a raw
//! decoder that skips the framing magic still sees a coherent message.

use crate::Envelope;
use serde_json::{json, Value};

// ---- varint ----

fn put_varint(buf: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            buf.push(byte);
            return;
        }
        buf.push(byte | 0x80);
    }
}

fn get_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift = 0;
    for _ in 0..10 {
        let b = *buf.get(*pos)? as u64;
        *pos += 1;
        result |= (b & 0x7F) << shift;
        if b & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
    }
    None
}

// ---- field tags: (field_number << 3) | wire_type (2 = length-delimited, 0 = varint) ----

fn put_tag(buf: &mut Vec<u8>, field: u32, wire_type: u32) {
    put_varint(buf, ((field as u64) << 3) | wire_type as u64);
}

// ---- protobuf: envelope fields (all optional except kind) ----
// field 1  kind        string
// field 2  uin         uint64
// field 3  name        string
// field 4  caps        repeated string
// field 5  to          string
// field 6  body        bytes (JSON-encoded Value)
// field 7  step        string
// field 8  phase       string
// field 9  state       bytes (JSON-encoded Value)
// field 10 text        string
// field 11 recover     bytes (JSON-encoded Value)
// field 12 seq         uint64 (acked replies)
// field 13 from        uint64 (msg deliveries)
// field 14 reason      string (error replies)
// field 15 note        bool   (note acks)

fn put_string(buf: &mut Vec<u8>, field: u32, s: &str) {
    put_tag(buf, field, 2);
    put_varint(buf, s.len() as u64);
    buf.extend_from_slice(s.as_bytes());
}

fn put_bytes(buf: &mut Vec<u8>, field: u32, v: &Value) {
    let json = serde_json::to_vec(v).unwrap_or_default();
    put_tag(buf, field, 2);
    put_varint(buf, json.len() as u64);
    buf.extend_from_slice(&json);
}

/// Envelope → Value (via its own JSON contract — one source of truth)
/// → protobuf WITH framing ([0x0A][u32 LE len][msg]).
pub fn encode(envelope: &Envelope) -> Vec<u8> {
    let v = serde_json::from_str::<Value>(envelope.to_line().trim_end()).unwrap_or(json!({}));
    frame(encode_value(&v).unwrap_or_default())
}

/// Wrap a raw protobuf message with the wire framing.
pub fn frame(msg: Vec<u8>) -> Vec<u8> {
    let mut out = vec![0x0A];
    out.extend_from_slice(&(msg.len() as u32).to_le_bytes());
    out.extend_from_slice(&msg);
    out
}

const FIELD_NUMBERS: &[(&str, u32)] = &[
    ("kind", 1),
    ("uin", 2),
    ("name", 3),
    ("caps", 4),
    ("to", 5),
    ("body", 6),
    ("step", 7),
    ("phase", 8),
    ("state", 9),
    ("text", 10),
    ("recover", 11),
    ("seq", 12),
    ("from", 13),
    ("reason", 14),
    ("note", 15),
    ("pid", 16),
    ("token", 17),
];

fn field_of(key: &str) -> Option<u32> {
    FIELD_NUMBERS
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, n)| *n)
}

/// Any envelope-shaped Value (agent send OR kernel reply) → protobuf.
/// Nulls are skipped; `caps` encodes as repeated strings; every other
/// value as length-delimited JSON bytes.
pub fn encode_value(v: &Value) -> Result<Vec<u8>, String> {
    let obj = v.as_object().ok_or("proto: envelope must be an object")?;
    let mut msg = Vec::new();
    for (k, val) in obj {
        let field = field_of(k).ok_or(format!("proto: unknown field '{k}'"))?;
        if val.is_null() {
            continue;
        }
        match k.as_str() {
            "kind" | "name" | "to" | "step" | "phase" | "text" | "reason" | "token" => {
                put_string(&mut msg, field, val.as_str().unwrap_or_default());
            }
            "uin" | "seq" | "from" | "pid" => {
                put_tag(&mut msg, field, 0);
                put_varint(&mut msg, val.as_u64().unwrap_or(0));
            }
            "note" => {
                put_tag(&mut msg, field, 0);
                put_varint(&mut msg, if val.as_bool().unwrap_or(false) { 1 } else { 0 });
            }
            "caps" => {
                if let Some(arr) = val.as_array() {
                    for c in arr {
                        if let Some(s) = c.as_str() {
                            put_string(&mut msg, field, s);
                        }
                    }
                }
            }
            _ => put_bytes(&mut msg, field, val),
        }
    }
    Ok(msg)
}

/// Decode ONE protobuf message (framing already consumed by the caller)
/// into its raw JSON Value — NO schema check. The caller decides whether
/// to enforce the Envelope contract: the kernel validates agent envelopes
/// via handle_value; the agent's reader accepts kernel replies verbatim,
/// exactly like the JSON/msgpack readers. Field order is irrelevant;
/// unknown fields are skipped (proto forward-compat); the encoder is
/// never the enforcement point.
pub fn decode_raw(msg: &[u8]) -> Result<Value, String> {
    let mut kind: Option<String> = None;
    let mut uin: u64 = 0;
    let mut name: Option<String> = None;
    let mut caps: Vec<String> = Vec::new();
    let mut to: Option<String> = None;
    let mut body: Option<Value> = None;
    let mut step: Option<String> = None;
    let mut phase: Option<String> = None;
    let mut state: Option<Value> = None;
    let mut text: Option<String> = None;
    let mut recover: Option<Value> = None;
    let mut reason: Option<String> = None;
    let mut note: Option<bool> = None;
    let mut seq: u64 = 0;
    let mut from: u64 = 0;
    let mut pid: u64 = 0;
    let mut seen_pid = false;
    let mut token: Option<String> = None;
    let mut seen_uin = false;
    let mut seen_seq = false;
    let mut seen_from = false;

    let mut pos = 0usize;
    while pos < msg.len() {
        let tag = get_varint(msg, &mut pos).ok_or("proto: truncated tag")?;
        let field = (tag >> 3) as u32;
        let wire_type = (tag & 7) as u32;
        match (field, wire_type) {
            (1, 2) => {
                let len = get_varint(msg, &mut pos).ok_or("proto: truncated len")? as usize;
                kind = Some(
                    String::from_utf8(msg.get(pos..pos + len).ok_or("proto: range")?.to_vec())
                        .map_err(|e| e.to_string())?,
                );
                pos += len;
            }
            (2, 0) => {
                uin = get_varint(msg, &mut pos).ok_or("proto: truncated uin")?;
                seen_uin = true;
            }
            (16, 0) => {
                pid = get_varint(msg, &mut pos).ok_or("proto: truncated pid")?;
                seen_pid = true;
            }
            (17, 2) => {
                let len = get_varint(msg, &mut pos).ok_or("proto: truncated len")? as usize;
                token = Some(
                    String::from_utf8(msg.get(pos..pos + len).ok_or("proto: range")?.to_vec())
                        .map_err(|e| e.to_string())?,
                );
                pos += len;
            }
            (3, 2) => {
                let len = get_varint(msg, &mut pos).ok_or("proto: truncated len")? as usize;
                name = Some(
                    String::from_utf8(msg.get(pos..pos + len).ok_or("proto: range")?.to_vec())
                        .map_err(|e| e.to_string())?,
                );
                pos += len;
            }
            (4, 2) => {
                let len = get_varint(msg, &mut pos).ok_or("proto: truncated len")? as usize;
                caps.push(
                    String::from_utf8(msg.get(pos..pos + len).ok_or("proto: range")?.to_vec())
                        .map_err(|e| e.to_string())?,
                );
                pos += len;
            }
            (5, 2) => {
                let len = get_varint(msg, &mut pos).ok_or("proto: truncated len")? as usize;
                to = Some(
                    String::from_utf8(msg.get(pos..pos + len).ok_or("proto: range")?.to_vec())
                        .map_err(|e| e.to_string())?,
                );
                pos += len;
            }
            (6, 2) => {
                let len = get_varint(msg, &mut pos).ok_or("proto: truncated len")? as usize;
                body = Some(
                    serde_json::from_slice(msg.get(pos..pos + len).ok_or("proto: range")?)
                        .map_err(|e| e.to_string())?,
                );
                pos += len;
            }
            (7, 2) => {
                let len = get_varint(msg, &mut pos).ok_or("proto: truncated len")? as usize;
                step = Some(
                    String::from_utf8(msg.get(pos..pos + len).ok_or("proto: range")?.to_vec())
                        .map_err(|e| e.to_string())?,
                );
                pos += len;
            }
            (8, 2) => {
                let len = get_varint(msg, &mut pos).ok_or("proto: truncated len")? as usize;
                phase = Some(
                    String::from_utf8(msg.get(pos..pos + len).ok_or("proto: range")?.to_vec())
                        .map_err(|e| e.to_string())?,
                );
                pos += len;
            }
            (9, 2) => {
                let len = get_varint(msg, &mut pos).ok_or("proto: truncated len")? as usize;
                state = Some(
                    serde_json::from_slice(msg.get(pos..pos + len).ok_or("proto: range")?)
                        .map_err(|e| e.to_string())?,
                );
                pos += len;
            }
            (10, 2) => {
                let len = get_varint(msg, &mut pos).ok_or("proto: truncated len")? as usize;
                text = Some(
                    String::from_utf8(msg.get(pos..pos + len).ok_or("proto: range")?.to_vec())
                        .map_err(|e| e.to_string())?,
                );
                pos += len;
            }
            (11, 2) => {
                let len = get_varint(msg, &mut pos).ok_or("proto: truncated len")? as usize;
                recover = Some(
                    serde_json::from_slice(msg.get(pos..pos + len).ok_or("proto: range")?)
                        .map_err(|e| e.to_string())?,
                );
                pos += len;
            }
            (12, 0) => {
                seq = get_varint(msg, &mut pos).ok_or("proto: truncated seq")?;
                seen_seq = true;
            }
            (13, 0) => {
                from = get_varint(msg, &mut pos).ok_or("proto: truncated from")?;
                seen_from = true;
            }
            (14, 2) => {
                let len = get_varint(msg, &mut pos).ok_or("proto: truncated len")? as usize;
                reason = Some(
                    String::from_utf8(msg.get(pos..pos + len).ok_or("proto: range")?.to_vec())
                        .map_err(|e| e.to_string())?,
                );
                pos += len;
            }
            (15, 0) => {
                let n = get_varint(msg, &mut pos).ok_or("proto: truncated note")?;
                note = Some(n != 0);
            }
            _ => {
                // unknown field (forward compat): skip by wire type
                match wire_type {
                    0 => {
                        get_varint(msg, &mut pos).ok_or("proto: truncated varint")?;
                    }
                    2 => {
                        let len = get_varint(msg, &mut pos).ok_or("proto: truncated len")? as usize;
                        pos += len;
                    }
                    other => return Err(format!("proto: unsupported wire type {other}")),
                }
            }
        }
    }

    let mut v = serde_json::Map::new();
    v.insert("kind".into(), json!(kind.ok_or("proto: missing 'kind'")?));
    if seen_uin {
        // only messages that CARRIED a uin get one — `register` rejects it
        v.insert("uin".into(), json!(uin));
    }
    if seen_pid {
        v.insert("pid".into(), json!(pid));
    }
    if let Some(t) = token {
        v.insert("token".into(), json!(t));
    }
    if seen_seq {
        v.insert("seq".into(), json!(seq));
    }
    if seen_from {
        v.insert("from".into(), json!(from));
    }
    let opt: Vec<(&str, Option<Value>)> = vec![
        ("name", name.map(Value::String)),
        ("to", to.map(Value::String)),
        ("body", body),
        ("step", step.map(Value::String)),
        ("phase", phase.map(Value::String)),
        ("state", state),
        ("text", text.map(Value::String)),
        ("recover", recover),
        ("reason", reason.map(Value::String)),
        ("note", note.map(Value::Bool)),
    ];
    for (k, val) in opt {
        if let Some(val) = val {
            v.insert(k.into(), val);
        }
    }
    v.insert("caps".into(), json!(caps));
    Ok(Value::Object(v))
}

/// Raw decode + the Envelope schema check (agent→kernel vocabulary). The
/// kernel's connection loops keep using this via `read_proto_frame`...
/// actually no: `read_proto_frame` uses `decode_raw` so the agent-side
/// reader accepts kernel replies; the kernel's `handle_value` re-checks
/// the Envelope contract itself. This wrapper remains for callers that
/// want the typed form.
pub fn decode(msg: &[u8]) -> Result<Envelope, String> {
    Envelope::from_value(&decode_raw(msg)?)
}

#[cfg(test)]
mod proto_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn roundtrip_every_kind() {
        let envs = vec![
            Envelope::Register {
                name: "a".into(),
                caps: vec!["send:b".into(), "send:c".into()],
                pid: 4242,
                token: Some("t".into()),
            },
            Envelope::Heartbeat {
                uin: 7,
                step: "3".into(),
                phase: "executing".into(),
            },
            Envelope::Welcome {
                uin: 6,
                recover: Some(json!({"step": 2, "n": 9})),
            },
            Envelope::Welcome {
                uin: 8,
                recover: None,
            },
            Envelope::Send {
                uin: 1,
                to: "b".into(),
                body: json!({"ping": 1, "nested": {"x": [1, 2, "three"]}}),
            },
            Envelope::Checkpoint {
                uin: 2,
                state: json!({"n": 9, "flag": false}),
            },
            Envelope::Note {
                uin: 3,
                text: "hello".into(),
            },
            Envelope::Done { uin: 4 },
            Envelope::Recovered { uin: 5 },
        ];
        for env in envs {
            let bytes = encode(&env);
            assert_eq!(bytes[0], 0x0A, "framing magic");
            let decoded = decode(&bytes[5..]).unwrap();
            assert_eq!(decoded, env, "{env:?}");
        }
    }

    #[test]
    fn unknown_field_is_skipped() {
        // hand-built: field 15 (string "junk") + a valid checkpoint
        let mut msg = Vec::new();
        put_string(&mut msg, 15, "junk");
        put_string(&mut msg, 1, "done");
        put_tag(&mut msg, 2, 0);
        put_varint(&mut msg, 9);
        let decoded = decode(&msg).unwrap();
        assert_eq!(decoded, Envelope::Done { uin: 9 });
    }

    #[test]
    fn kernel_replies_roundtrip_raw() {
        // kernel→agent replies are OUTSIDE the agent→kernel Envelope
        // vocabulary. Experiment 004's root cause: read_proto_frame ran
        // the Envelope schema over REPLIES, so the proto agent's reader
        // thread died on the very first welcome and every agent on the
        // first ack (heartbeat timeout / no progress). Replies must
        // survive encode → decode_raw verbatim.
        let replies = vec![
            json!({"kind": "welcome", "uin": 0u64, "recover": {"step_index": 2, "n": 9}}),
            json!({"kind": "welcome", "uin": 3u64}),
            json!({"kind": "sent", "to": "a"}),
            json!({"kind": "acked", "seq": 42u64}),
            json!({"kind": "acked", "note": true}),
            json!({"kind": "msg", "from": 1u64, "body": {"pong": 2}}),
            json!({"kind": "error", "reason": "agent 'x' is dead"}),
        ];
        for r in &replies {
            let framed = frame(encode_value(r).expect("encode"));
            let decoded = decode_raw(&framed[5..]).expect("decode_raw");
            // decode_raw always adds a caps:[] placeholder (forward-compat)
            let mut want = r.clone();
            want["caps"] = json!([]);
            assert_eq!(decoded, want, "{r:?}");
        }
        // and the Envelope wrapper still REJECTS reply kinds: they are
        // the kernel→agent family, validated nowhere on the agent side
        let sent = encode_value(&json!({"kind": "sent", "to": "a"})).unwrap();
        assert!(decode(&sent).is_err());
    }
}
