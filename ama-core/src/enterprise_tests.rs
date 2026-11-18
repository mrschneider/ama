use super::*;
use std::io::{Cursor, ErrorKind};
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

struct Temp(std::path::PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "ama-enterprise-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn kernel(dir: &Temp) -> Kernel {
    Kernel::new(
        &dir.0.join("s.sock"),
        &dir.0.join("ledger.jsonl"),
        "/nonexistent",
        100,
        1000,
        0,
    )
    .unwrap()
}
fn entry(k: &Kernel, uin: u64, name: &str) -> (Arc<Outbound>, UnixStream) {
    let (tx, rx) = UnixStream::pair().unwrap();
    let out = spawn_writer(k.ledger.clone(), Peer::Unix(tx), Wire::Json);
    let process = ProcEntry {
        uin,
        name: name.into(),
        pid: 0,
        caps: vec![],
        manifest_caps: None,
        auth_token: None,
        tcp_addr: None,
        spawned_at: Instant::now(),
        granted: vec![],
        revoked: vec![],
        state: ProcState::Running,
        last_hb: Instant::now(),
        last_step: String::new(),
        last_phase: "executing".into(),
        stuck_sweeps: 0,
        respawns: 0,
        last_checkpoint: None,
        task_path: "/dev/null".into(),
        out: Some(out.clone()),
        wire: Wire::Json,
        isolation: None,
        priority: 5,
        dtn: false,
    };
    k.agents
        .lock()
        .unwrap()
        .insert(uin, Arc::new(Mutex::new(process)));
    k.bind_name(name, uin);
    (out, rx)
}

/// Register a SENDER: an entry that holds the `send` capability. The
/// kernel authorizes a send inside the process table (F11), so a test
/// that drives `route_send` directly must give the SENDER an entry too.
fn sender(k: &Kernel, uin: u64, name: &str) {
    let (tx, _rx) = UnixStream::pair().unwrap();
    let out = spawn_writer(k.ledger.clone(), Peer::Unix(tx), Wire::Json);
    let process = ProcEntry {
        uin,
        name: name.into(),
        pid: 0,
        caps: vec!["send".into()],
        manifest_caps: None,
        auth_token: None,
        tcp_addr: None,
        spawned_at: Instant::now(),
        granted: vec![],
        revoked: vec![],
        state: ProcState::Running,
        last_hb: Instant::now(),
        last_step: String::new(),
        last_phase: "executing".into(),
        stuck_sweeps: 0,
        respawns: 0,
        last_checkpoint: None,
        task_path: "/dev/null".into(),
        out: Some(out),
        wire: Wire::Json,
        isolation: None,
        priority: 5,
        dtn: false,
    };
    k.agents
        .lock()
        .unwrap()
        .insert(uin, Arc::new(Mutex::new(process)));
    k.bind_name(name, uin);
}

#[test]
fn binary_lengths_are_rejected_before_reading_any_body_on_every_frame() {
    struct HeaderOnly {
        bytes: Cursor<Vec<u8>>,
        body_reads: usize,
    }
    impl Read for HeaderOnly {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.bytes.position() >= 5 {
                self.body_reads += 1;
                return Err(io::Error::other("body must not be read"));
            }
            self.bytes.read(buffer)
        }
    }
    for magic in [0xff, 0x0a] {
        let mut raw = vec![magic];
        raw.extend_from_slice(&(MAX_FRAME as u32 + 1).to_le_bytes());
        let mut input = HeaderOnly {
            bytes: Cursor::new(raw),
            body_reads: 0,
        };
        let error = if magic == 0xff {
            read_msgpack_frame(&mut input).unwrap_err()
        } else {
            read_proto_frame(&mut input).unwrap_err()
        };
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert_eq!(input.body_reads, 0);
    }
}

#[test]
fn total_binary_deadline_expires_despite_progress() {
    let (tx, mut rx) = UnixStream::pair().unwrap();
    let sender = std::thread::spawn(move || {
        let mut tx = tx;
        for _ in 0..10 {
            if tx.write_all(&[0]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(15));
        }
    });
    let mut peer = Peer::Unix(rx.try_clone().unwrap());
    let mut bytes = [0; 10];
    let result = PeerDeadline::until(&mut peer, Instant::now() + Duration::from_millis(45))
        .read_exact(&mut bytes);
    assert!(result.is_err());
    rx.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let mut rest = Vec::new();
    let _ = rx.read_to_end(&mut rest);
    sender.join().unwrap();
}

#[test]
fn connection_admission_is_shared_bounded_and_releases_on_drop() {
    let limits = resources::ResourceLimits {
        max_connections: 2,
        max_connections_per_peer: 1,
        ..Default::default()
    };
    let gate = Arc::new(resources::Connections::new(limits));
    let first = gate.acquire("one".into()).unwrap();
    assert!(gate.acquire("one".into()).is_none());
    let second = gate.acquire("two".into()).unwrap();
    assert!(gate.acquire("three".into()).is_none());
    drop(first);
    assert!(gate.acquire("three".into()).is_some());
    drop(second);
    assert_eq!(gate.stats()["active"], 0);
}

#[test]
fn shared_byte_reservations_include_inflight_and_release_on_drop() {
    let global = Arc::new(resources::ByteBudget::new(10));
    let first = global.reserve(6).unwrap();
    assert!(global.reserve(5).is_none());
    assert_eq!(global.usage().0, 6);
    drop(first);
    let second = global.reserve(10).unwrap();
    assert_eq!(global.usage().0, 10);
    drop(second);
    assert_eq!(global.usage().0, 0);
}

#[test]
fn actual_outbound_keeps_global_budget_until_frame_is_dropped() {
    let dir = Temp::new();
    let ledger = Arc::new(Ledger::open(&dir.0.join("out")).unwrap());
    ledger.outbound_budget.set_limit(10).unwrap();
    let out = Outbound {
        wire: Wire::Json,
        cap: 10,
        state: Mutex::new(OutboundState {
            frames: Default::default(),
            bytes: 0,
        }),
        idle: Default::default(),
        closed: Default::default(),
        budget: Mutex::new(Arc::new(resources::ByteBudget::new(10))),
        ledger: ledger.clone(),
    };
    out.push(vec![1; 6]).unwrap();
    let inflight = out.pop().unwrap();
    assert_eq!(ledger.outbound_budget.usage().0, 6);
    assert!(out.push(vec![1; 5]).is_err());
    drop(inflight);
    out.push(vec![1; 5]).unwrap();
    out.close();
    assert_eq!(ledger.outbound_budget.usage().0, 0);
}

#[test]
fn contended_kernel_send_charges_byte_rate_only_once() {
    let dir = Temp::new();
    let k = kernel(&dir);
    let (out, _rx) = entry(&k, 2, "dest");
    sender(&k, 1, "src");
    let body = json!({"payload": "x".repeat(580)});
    let bytes = serde_json::to_vec(&body).unwrap().len();
    {
        let mut d = k.delivery.lock().unwrap();
        d.set_byte_rate(1, Some(1000));
        d.link_bytes_per_tick = Some(1000);
        d.refill_link();
        assert!(d.link_ready(1000));
    }
    k.route_send(1, "dest", &body).unwrap();
    let d = k.delivery.lock().unwrap();
    assert_eq!(d.queued_len(), 1);
    assert_eq!(d.accounting.queued_bytes, bytes as u64);
    drop(d);
    out.close();
}

#[test]
fn unschedulable_head_is_refused_without_blocking_smaller_work() {
    let mut d = qos::DeliverySystem::new(10, Duration::from_secs(30));
    d.link_bytes_per_tick = Some(100);
    d.refill_link();
    assert!(d.schedule(1, 2, json!({}), 101).is_err());
    d.schedule(1, 2, json!({}), 50).unwrap();
    assert_eq!(d.pop_next().unwrap().bytes, 50);
    assert_eq!(d.queued_len(), 0);
}

#[test]
fn dropped_queued_message_does_not_subtract_the_remaining_queue_twice() {
    let mut d = qos::DeliverySystem::new(10, Duration::from_secs(30));
    d.schedule(1, 2, json!({}), 100).unwrap();
    d.schedule(1, 2, json!({}), 100).unwrap();
    let message = d.pop_next().unwrap();
    d.record_queued_drop(message.bytes);
    assert_eq!(d.accounting.queued_bytes, 100);
}

#[test]
fn dedicated_scheduler_delivers_without_a_watchdog_sweep() {
    let dir = Temp::new();
    let k = Arc::new(kernel(&dir));
    let (out, rx) = entry(&k, 2, "dest");
    sender(&k, 1, "src");
    {
        let mut d = k.delivery.lock().unwrap();
        d.link_bytes_per_tick = Some(10000);
        d.refill_link();
        assert!(d.link_ready(10000));
    }
    k.route_send(1, "dest", &json!({"work": 1})).unwrap();
    Kernel::start_delivery_scheduler(&k);
    rx.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut reader = BufReader::new(rx);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&line).unwrap()["body"]["work"],
        1
    );
    out.close();
}

#[test]
fn custody_bytes_are_bounded_by_global_sender_and_destination() {
    let mut d = qos::DeliverySystem::new(100, Duration::from_secs(60));
    d.bundles.max_bytes = 20;
    d.bundles.max_sender_bytes = 10;
    d.bundles.max_destination_bytes = 12;
    d.store(1, 2, json!("123456"), 5, None).unwrap(); // 8 encoded bytes
    assert!(d.store(1, 3, json!("123456"), 5, None).is_err());
    assert!(d.store(4, 2, json!("123456"), 5, None).is_err());
    d.store(4, 5, json!("123456"), 5, None).unwrap();
    assert!(d.store(6, 7, json!("123456"), 5, None).is_err());
    assert_eq!(d.bundles.bytes(), 16);
    d.drain_for(2);
    d.store(1, 3, json!("123456"), 5, None).unwrap();
}

#[test]
fn indexed_custody_ack_checks_owner_fragment_and_restores_bytes() {
    let mut d = qos::DeliverySystem::new(100, Duration::from_secs(60));
    for i in 0..3 {
        d.store_routed(
            1,
            2,
            json!({"n":i}),
            5,
            None,
            Some(9),
            0,
            42,
            Some(qos::FragMeta {
                id: 42,
                index: i,
                total: 3,
            }),
        )
        .unwrap();
    }
    let bytes = d.bundles.bytes();
    assert_eq!(d.ack_custody(42, Some(1), 10), 0);
    assert_eq!(d.ack_custody(42, Some(1), 9), 1);
    assert!(d.bundles.bytes() < bytes);
    assert_eq!(d.ack_custody(42, None, 9), 2);
    assert_eq!(d.bundles.bytes(), 0);
}

#[test]
fn recovery_populates_checkpoint_hits_and_misses_and_updates_new_values() {
    let dir = Temp::new();
    let path = dir.0.join("ledger");
    let ledger = Ledger::open(&path).unwrap();
    ledger
        .append_durable("checkpoint", json!({"uin":1,"state":{"n":1}}))
        .unwrap();
    drop(ledger);
    let ledger = Ledger::open(&path).unwrap();
    assert_eq!(ledger.last_checkpoint(1).unwrap()["n"], 1);
    for _ in 0..100 {
        assert!(ledger.last_checkpoint(2).is_none());
    }
    ledger
        .append_durable("checkpoint", json!({"uin":2,"state":{"n":2}}))
        .unwrap();
    assert_eq!(ledger.last_checkpoint(2).unwrap()["n"], 2);
}

#[test]
fn snapshot_rotation_preserves_history_sequence_and_checkpoint_recovery() {
    let dir = Temp::new();
    let path = dir.0.join("ledger");
    let ledger = Ledger::open(&path).unwrap();
    ledger.set_segment_bytes(150);
    for n in 0..20 {
        ledger
            .append_durable("checkpoint", json!({"uin":1,"state":{"n":n}}))
            .unwrap();
    }
    let before = ledger.read_all();
    assert_eq!(before.len(), 20);
    assert!(std::fs::read_dir(&dir.0)
        .unwrap()
        .filter_map(Result::ok)
        .any(|e| e.file_name().to_string_lossy().contains("segment-")));
    drop(ledger);
    let ledger = Ledger::open(&path).unwrap();
    assert_eq!(ledger.last_checkpoint(1).unwrap()["n"], 19);
    assert_eq!(ledger.append_durable("next", json!({})).unwrap().seq, 21);
    assert_eq!(ledger.read_all().len(), 21);
}

#[test]
fn interrupted_rotation_activates_the_durable_snapshot() {
    let dir = Temp::new();
    let path = dir.0.join("ledger");
    let ledger = Ledger::open(&path).unwrap();
    ledger
        .append_durable("checkpoint", json!({"uin":7,"state":{"n":1}}))
        .unwrap();
    ledger.rotate().unwrap();
    drop(ledger);
    std::fs::rename(&path, Ledger::suffixed(&path, ".rotate.tmp")).unwrap();
    let ledger = Ledger::open(&path).unwrap();
    assert_eq!(ledger.last_checkpoint(7).unwrap()["n"], 1);
    assert_eq!(ledger.append_durable("next", json!({})).unwrap().seq, 2);
}

#[test]
fn durable_failure_does_not_publish_a_checkpoint_or_allow_future_appends() {
    let ledger = Ledger::open(std::path::Path::new("/dev/null")).unwrap();
    assert!(ledger
        .append_durable("checkpoint", json!({"uin":1,"state":{}}))
        .is_err());
    assert!(ledger.last_checkpoint(1).is_none());
    assert!(!ledger.is_healthy());
    assert!(ledger.append("next", json!({})).is_err());
}

#[test]
fn externally_replaced_ledger_is_detected_on_the_next_append() {
    let dir = Temp::new();
    let path = dir.0.join("ledger");
    let ledger = Ledger::open(&path).unwrap();
    ledger.append("first", json!({})).unwrap();
    std::fs::rename(&path, dir.0.join("old")).unwrap();
    ledger
        .append_durable("checkpoint", json!({"uin":1,"state":{}}))
        .unwrap();
    assert_eq!(ledger.read_all().len(), 1);
    assert_eq!(ledger.read_all()[0].ev, "checkpoint");
}

/// F11: the send path authorizes INSIDE the process table, so a sender
/// without the capability is refused and the refusal is journaled — the
/// denial must never be silent.
#[test]
fn a_send_without_the_capability_is_refused_and_journaled() {
    let dir = Temp::new();
    let k = kernel(&dir);
    let (_out, _rx) = entry(&k, 2, "dest");
    // the sender holds NO capability at all
    let (tx, _rx2) = UnixStream::pair().unwrap();
    let out = spawn_writer(k.ledger.clone(), Peer::Unix(tx), Wire::Json);
    k.agents.lock().unwrap().insert(
        1,
        Arc::new(Mutex::new(ProcEntry {
            uin: 1,
            name: "src".into(),
            pid: 0,
            caps: vec![],
            manifest_caps: None,
            auth_token: None,
            tcp_addr: None,
            spawned_at: Instant::now(),
            granted: vec![],
            revoked: vec![],
            state: ProcState::Running,
            last_hb: Instant::now(),
            last_step: String::new(),
            last_phase: "executing".into(),
            stuck_sweeps: 0,
            respawns: 0,
            last_checkpoint: None,
            task_path: "/dev/null".into(),
            out: Some(out),
            wire: Wire::Json,
            isolation: None,
            priority: 5,
            dtn: false,
        })),
    );
    k.bind_name("src", 1);
    let err = k
        .route_send(1, "dest", &json!({"work": 1}))
        .expect_err("a sender without the capability must be refused");
    assert!(err.contains("not granted"), "{err}");
    let denials: Vec<_> = k
        .ledger
        .read_all()
        .into_iter()
        .filter(|e| e.ev == "cap_denied")
        .collect();
    assert_eq!(denials.len(), 1, "the refusal is journaled exactly once");
    assert_eq!(denials[0].detail["needed"], "send:dest");
}

/// The capability verdict must be the FIRST question: an unauthorized
/// sender learns nothing about whether the target exists.
#[test]
fn an_unauthorized_sender_does_not_learn_whether_the_target_exists() {
    let dir = Temp::new();
    let k = kernel(&dir);
    let (tx, _rx) = UnixStream::pair().unwrap();
    let out = spawn_writer(k.ledger.clone(), Peer::Unix(tx), Wire::Json);
    k.agents.lock().unwrap().insert(
        1,
        Arc::new(Mutex::new(ProcEntry {
            uin: 1,
            name: "src".into(),
            pid: 0,
            caps: vec![],
            manifest_caps: None,
            auth_token: None,
            tcp_addr: None,
            spawned_at: Instant::now(),
            granted: vec![],
            revoked: vec![],
            state: ProcState::Running,
            last_hb: Instant::now(),
            last_step: String::new(),
            last_phase: "executing".into(),
            stuck_sweeps: 0,
            respawns: 0,
            last_checkpoint: None,
            task_path: "/dev/null".into(),
            out: Some(out),
            wire: Wire::Json,
            isolation: None,
            priority: 5,
            dtn: false,
        })),
    );
    k.bind_name("src", 1);
    // "ghost" is NOT in the table
    let err = k
        .route_send(1, "ghost", &json!({}))
        .expect_err("an unauthorized sender is refused");
    assert!(
        err.contains("not granted"),
        "the capability verdict comes first, not the target lookup: {err}"
    );
}

/// The ledger frames a record (payload + newline) in ONE write, so a
/// record is always exactly one line — even when the payload carries
/// newlines.
#[test]
fn every_record_is_exactly_one_line_even_with_newlines_in_the_payload() {
    let dir = Temp::new();
    let path = dir.0.join("ledger.jsonl");
    let ledger = Ledger::open(&path).unwrap();
    for i in 0..50 {
        ledger
            .append("tick", json!({"i": i, "text": "a\nb\nc"}))
            .unwrap();
    }
    let raw = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        raw.lines().count(),
        50,
        "one line per record — no split by an embedded newline"
    );
    assert!(raw.ends_with('\n'), "the last record is terminated");
    let parsed: Vec<LedgerEvent> = raw
        .lines()
        .map(|l| serde_json::from_str(l).expect("every line parses"))
        .collect();
    assert_eq!(parsed.len(), 50);
    assert_eq!(parsed[7].detail["text"], "a\nb\nc");
}

/// Retention: the archives are counted, and pruning keeps the NEWEST N.
#[test]
fn ledger_stats_count_archives_and_pruning_keeps_the_newest() {
    let dir = Temp::new();
    let path = dir.0.join("ledger");
    let ledger = Ledger::open(&path).unwrap();
    for n in 0..3 {
        ledger
            .append("checkpoint", json!({"uin": 1, "state": {"n": n}}))
            .unwrap();
        ledger.rotate().unwrap();
    }
    let stats = ledger.stats();
    assert_eq!(stats["archives"], 3);
    assert_eq!(stats["healthy"], true);
    assert!(stats["total_bytes"].as_u64().unwrap() > 0);
    let removed = ledger.prune_archives(1).unwrap();
    assert_eq!(removed.len(), 2);
    assert_eq!(ledger.stats()["archives"], 1);
    // the ACTIVE file and the newest archive survive: recovery still works
    assert_eq!(ledger.last_checkpoint(1).unwrap()["n"], 2);
    let all = ledger.read_all();
    assert!(
        all.iter()
            .any(|e| e.ev == "checkpoint" && e.detail["state"]["n"] == 2),
        "the surviving archive still carries the latest checkpoint"
    );
}

/// The kernel snapshot the `ama stats` verb serves: process table by
/// state, journal growth and the connection budgets.
#[test]
fn kernel_stats_report_the_table_the_journal_and_the_budgets() {
    let dir = Temp::new();
    let k = kernel(&dir);
    let (_out, _rx) = entry(&k, 2, "dest");
    sender(&k, 1, "src");
    k.ledger.append("tick", json!({})).unwrap();
    let stats = k.stats();
    assert_eq!(stats["agents"]["total"], 2);
    assert_eq!(stats["agents"]["by_state"]["running"], 2);
    assert_eq!(stats["ledger"]["healthy"], true);
    assert_eq!(stats["ledger"]["seq"], 1);
    assert!(stats["uptime_ms"].as_u64().is_some());
    assert!(stats["connections"].get("active").is_some());
}

#[test]
fn occupied_tcp_port_fails_before_exposing_the_unix_sockets() {
    let dir = Temp::new();
    let mut k = kernel(&dir);
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    k.tcp_addr = Some(listener.local_addr().unwrap().to_string());
    let socket = k.socket_path.clone();

    let error = Router::serve_full(k, &[]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::AddrInUse);
    assert!(!socket.exists());
    assert!(!control_socket_path(&socket).exists());
}

#[test]
fn readiness_requires_the_manifest_agents_and_a_healthy_journal() {
    let dir = Temp::new();
    let mut k = kernel(&dir);
    k.expected_agents = 2;
    let _first = entry(&k, 1, "first");
    assert_eq!(k.health()["healthy"], true);
    assert_eq!(k.health()["ready"], false, "one launch is missing");
    let _second = entry(&k, 2, "second");
    let process = k.agents.lock().unwrap()[&2].clone();

    for (state, ready) in [
        (ProcState::Starting, false),
        (ProcState::Running, true),
        (ProcState::Dead, false),
        (ProcState::Completed, true),
    ] {
        process.lock().unwrap().state = state;
        assert_eq!(k.health()["ready"], ready);
    }

    k.ledger.failed.store(true, Ordering::Release);
    assert_eq!(k.health()["healthy"], false);
    assert_eq!(k.health()["ready"], false);
}

/// The journal tail: the newest events, oldest first, filtered.
#[test]
fn the_journal_tail_returns_the_newest_events_filtered() {
    let dir = Temp::new();
    let path = dir.0.join("ledger");
    let ledger = Ledger::open(&path).unwrap();
    for i in 0..50u64 {
        ledger
            .append(
                if i % 5 == 0 {
                    "checkpoint"
                } else {
                    "delivered"
                },
                json!({"i": i, "from": 1, "to": 2, "uin": 1}),
            )
            .unwrap();
    }
    let tail = ledger.tail(10, None, None);
    assert_eq!(tail.len(), 10);
    assert!(
        tail.windows(2).all(|w| w[0].seq < w[1].seq),
        "the tail is ordered oldest first"
    );
    assert_eq!(tail.last().unwrap().seq, 50, "the newest event is last");
    assert_eq!(tail.first().unwrap().seq, 41);

    let only_checkpoints = ledger.tail(100, Some("checkpoint"), None);
    assert!(!only_checkpoints.is_empty());
    assert!(only_checkpoints.iter().all(|e| e.ev == "checkpoint"));
    assert_eq!(
        only_checkpoints.len(),
        10,
        "50 events, every 5th is a checkpoint"
    );

    let by_uin = ledger.tail(100, None, Some(1));
    assert!(!by_uin.is_empty());
    assert!(by_uin
        .iter()
        .all(|e| { e.detail["uin"] == 1 || e.detail["from"] == 1 || e.detail["to"] == 1 }));

    let nothing = ledger.tail(10, Some("no_such_event"), None);
    assert!(
        nothing.is_empty(),
        "a filter that matches nothing returns nothing"
    );
}

/// The tail reads ACROSS a rotation: the newest segment plus the archives.
#[test]
fn the_journal_tail_spans_the_rotation_boundary() {
    let dir = Temp::new();
    let path = dir.0.join("ledger");
    let ledger = Ledger::open(&path).unwrap();
    for i in 0..10u64 {
        ledger.append("tick", json!({"i": i})).unwrap();
    }
    ledger.rotate().unwrap();
    for i in 10..20u64 {
        ledger.append("tick", json!({"i": i})).unwrap();
    }
    let tail = ledger.tail(15, None, None);
    assert_eq!(tail.len(), 15, "the tail spans both segments");
    assert!(
        tail.windows(2).all(|w| w[0].seq < w[1].seq),
        "the order survives the segment boundary"
    );
    assert_eq!(tail.last().unwrap().seq, 20);
}

#[test]
fn journal_tail_keeps_chunk_spanning_records_and_ignores_an_unfinished_append() {
    let dir = Temp::new();
    let path = dir.0.join("ledger");
    let ledger = Ledger::open(&path).unwrap();
    let payload = "α".repeat(13_000);

    ledger
        .append("note", json!({"from": 1, "payload": &payload}))
        .unwrap();
    ledger.append("note", json!({"from": 2})).unwrap();
    ledger.rotate().unwrap();
    ledger
        .append("note", json!({"from": 1, "payload": &payload}))
        .unwrap();
    ledger.append("note", json!({"from": 1})).unwrap();

    // Simulate observing the active file during an incomplete append.
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    let unfinished = json!({
        "seq": 5, "ts_ms": 0, "ev": "note",
        "detail": {"from": 1, "payload": &payload},
    });
    std::io::Write::write_all(&mut file, unfinished.to_string().as_bytes()).unwrap();

    let events = ledger.tail(10, Some("note"), Some(1));
    assert_eq!(
        events.iter().map(|ev| ev.seq).collect::<Vec<_>>(),
        [1, 3, 4]
    );
    assert_eq!(events[0].detail["payload"], payload);
    assert_eq!(events[1].detail["payload"], payload);
    assert_eq!(ledger.tail(1, None, None)[0].seq, 4);
}

/// The wakeable inbox: the waiter is woken by the push, and ONLY the
/// matching frame is removed.
#[test]
fn the_inbox_wakes_the_waiter_and_keeps_the_other_frames() {
    use crate::inbox::Inbox;
    let inbox: std::sync::Arc<Inbox<Value>> = std::sync::Arc::new(Inbox::new());
    // the non-matching frame is queued FIRST: it must survive the wait
    inbox.push(json!({"kind": "acked"}));
    let t0 = Instant::now();
    let producer = {
        let inbox = inbox.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            inbox.push(json!({"kind": "msg", "body": 1}));
        })
    };
    let got = inbox.pop_matching(Duration::from_secs(5), |v| {
        v.get("kind").and_then(Value::as_str) == Some("msg")
    });
    let waited = t0.elapsed();
    assert!(got.is_some(), "the waiter was woken by the push");
    assert!(
        waited < Duration::from_secs(1),
        "it waited for the frame, not a timeout"
    );
    assert_eq!(inbox.len(), 1, "the non-matching frame stays queued");
    let ack = inbox.pop_matching(Duration::from_millis(100), |v| {
        v.get("kind").and_then(Value::as_str) == Some("acked")
    });
    assert!(ack.is_some(), "the other frame is still there");
    producer.join().unwrap();
}

/// A timeout returns None — it never blocks forever.
#[test]
fn the_inbox_times_out_instead_of_blocking_forever() {
    use crate::inbox::Inbox;
    let inbox: std::sync::Arc<Inbox<Value>> = std::sync::Arc::new(Inbox::new());
    let t0 = Instant::now();
    let got = inbox.pop_matching(Duration::from_millis(80), |v| {
        v.get("kind").and_then(Value::as_str) == Some("never")
    });
    assert!(got.is_none());
    assert!(
        t0.elapsed() >= Duration::from_millis(70),
        "it waited the timeout"
    );
}

/// The agentd's inbox must not lose a pending ack: the old poll popped
/// from the front and DISCARDED everything that did not match.
#[test]
fn the_inbox_never_discards_a_frame_that_did_not_match() {
    use crate::inbox::Inbox;
    let inbox: std::sync::Arc<Inbox<Value>> = std::sync::Arc::new(Inbox::new());
    inbox.push(json!({"kind": "acked", "seq": 1}));
    inbox.push(json!({"kind": "msg", "body": "x"}));
    let msg = inbox.pop_matching(Duration::from_millis(50), |v| {
        v.get("kind").and_then(Value::as_str) == Some("msg")
    });
    assert!(msg.is_some());
    assert_eq!(inbox.len(), 1, "the ack survived the msg wait");
    let ack = inbox.pop_matching(Duration::from_millis(50), |v| {
        v.get("kind").and_then(Value::as_str) == Some("acked")
    });
    assert!(ack.is_some(), "the ack is still there");
}

#[test]
fn reconnects_share_agent_budget_until_last_reservation_drops() {
    let dir = Temp::new();
    let ledger = Ledger::open(&dir.0.join("ledger.jsonl")).unwrap();
    ledger.outbound_agent_limit.store(10, Ordering::Relaxed);
    let first = ledger.agent_budget(7);
    let held = first.reserve(8).unwrap();
    drop(first);
    let second = ledger.agent_budget(7);
    assert!(second.reserve(3).is_none());
    assert!(ledger.agent_budget(8).reserve(10).is_some());
    drop(held);
    assert!(second.reserve(10).is_some());
}

#[test]
fn connection_reservation_survives_reader_until_writer_exits() {
    let dir = Temp::new();
    let ledger = Arc::new(Ledger::open(&dir.0.join("ledger.jsonl")).unwrap());
    let connections = Arc::new(resources::Connections::new(resources::ResourceLimits {
        max_connections: 1,
        max_connections_per_peer: 1,
        ..Default::default()
    }));
    let lease = Arc::new(connections.acquire("peer".into()).unwrap());
    let (tx, _rx) = UnixStream::pair().unwrap();
    let out = spawn_writer_reserved(ledger, Peer::Unix(tx), Wire::Json, Some(lease.clone()));
    drop(lease);
    assert!(connections.acquire("peer".into()).is_none());
    out.close();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if connections.acquire("peer".into()).is_some() {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
}
