//! The Anthropic arches against a stand-in API on loopback: what goes on the
//! wire, what comes back off it, what is refused before anything is sent, and
//! what never appears anywhere — the key.
//!
//! No live call is possible here and none is wanted: there is no key on this
//! machine. Everything the first-party adapter does over HTTP is measured
//! against [`Fake`], a hand-written HTTP/1.1 responder that records the
//! **headers** as well as the bodies, because two of the three things this
//! adapter must get right (`anthropic-version`, `x-api-key`) are headers. The
//! Bedrock arch is unit-tested where it can be — the manifest and the request
//! shape — because its transport is the AWS SDK and there is no credential on
//! this machine to drive it with.
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use vk_arch_anthropic::{
    bedrock, AnthropicAdapter, AnthropicConfig, KeySource, SecretString, ANTHROPIC_VERSION,
    DEFAULT_MODEL, MAX_OUTPUT_TOKENS,
};
use vk_contracts::arch::{Determinism, Locality};
use vk_contracts::labels::Scope;
use vk_kernel::arch::{AdapterError, ArchAdapter, MountSpec};

/// The key every test drives the adapter with. Shaped like a real one so that
/// "the key never appears" is a claim about a string that would be noticed.
const KEY: &str = "sk-ant-api03-TESTKEYTESTKEYTESTKEYTESTKEY";

// ---------------------------------------------------------------- the fake

/// What the stand-in answers with.
#[derive(Debug, Clone)]
struct Canned {
    /// `content` of the `/v1/messages` answer.
    content: Value,
    stop_reason: String,
    input_tokens: u32,
    output_tokens: u32,
    /// What `/v1/messages/count_tokens` reports, or `None` to make it fail
    /// the way a rate-limited or unreachable endpoint would.
    count: Option<u32>,
    /// An error object to answer `/v1/messages` with instead, and its status.
    error: Option<(u16, Value)>,
    /// Answer `/v1/messages` with a redirect of this status to this origin
    /// instead. The adapter must **not** follow it: `x-api-key` is a custom
    /// header and reqwest's default policy would carry it across the hop.
    redirect_to: Option<(u16, String)>,
}

impl Default for Canned {
    fn default() -> Canned {
        Canned {
            // Three blocks, one of them a thinking block with no text in it:
            // `display` defaults to `omitted` on the Claude 5 family, so this
            // is the ordinary shape and the adapter must skip it rather than
            // concatenate an empty string into the answer.
            content: json!([
                {"type": "thinking", "thinking": "", "signature": ""},
                {"type": "text", "text": "the first half"},
                {"type": "text", "text": " and the second"},
            ]),
            stop_reason: "end_turn".into(),
            input_tokens: 1234,
            output_tokens: 56,
            count: Some(1234),
            error: None,
            redirect_to: None,
        }
    }
}

/// One request the stand-in was sent.
#[derive(Debug, Clone)]
struct Seen {
    path: String,
    headers: BTreeMap<String, String>,
    body: Value,
}

struct Fake {
    base_url: String,
    log: Arc<Mutex<Vec<Seen>>>,
    stop: Arc<AtomicBool>,
}

impl Drop for Fake {
    fn drop(&mut self) {
        // The serving thread is blocked in `accept`; one connection wakes it
        // so it can see the flag. Nothing is joined: a failing test must not
        // also hang.
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.base_url.trim_start_matches("http://"));
    }
}

impl Fake {
    fn start(canned: Canned) -> Fake {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let base_url = format!("http://{}", listener.local_addr().expect("addr"));
        let log: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let (l, s) = (log.clone(), stop.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if s.load(Ordering::SeqCst) {
                    return;
                }
                if let Ok(stream) = stream {
                    serve(stream, &canned, &l);
                }
            }
        });
        Fake {
            base_url,
            log,
            stop,
        }
    }

    fn seen(&self, path: &str) -> Vec<Seen> {
        self.log
            .lock()
            .expect("log")
            .iter()
            .filter(|s| s.path == path)
            .cloned()
            .collect()
    }

    /// The one request to `path`, or a failure naming how many there were.
    fn only(&self, path: &str) -> Seen {
        let all = self.seen(path);
        assert_eq!(all.len(), 1, "expected one {path}, saw {}", all.len());
        all.into_iter().next().expect("one")
    }
}

fn serve(mut stream: TcpStream, canned: &Canned, log: &Arc<Mutex<Vec<Seen>>>) {
    let Some((path, headers, body)) = read_request(&stream) else {
        return;
    };
    let parsed: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    log.lock().expect("log").push(Seen {
        path: path.clone(),
        headers,
        body: parsed.clone(),
    });
    match path.as_str() {
        "/v1/messages/count_tokens" => match canned.count {
            Some(n) => respond(&mut stream, 200, &json!({ "input_tokens": n })),
            None => respond(
                &mut stream,
                429,
                &json!({"type": "error", "error": {"type": "rate_limit_error", "message": "slow down"}}),
            ),
        },
        "/v1/messages" => match (&canned.error, &canned.redirect_to) {
            (_, Some((status, to))) => redirect(&mut stream, *status, &format!("{to}/v1/messages")),
            (Some((status, body)), _) => respond(&mut stream, *status, body),
            (None, None) => respond(
                &mut stream,
                200,
                &json!({
                    "id": "msg_01FAKE",
                    "type": "message",
                    "role": "assistant",
                    "model": parsed["model"],
                    "content": canned.content,
                    "stop_reason": canned.stop_reason,
                    "stop_sequence": null,
                    "usage": {
                        "input_tokens": canned.input_tokens,
                        "output_tokens": canned.output_tokens,
                        "cache_creation_input_tokens": 0,
                        "cache_read_input_tokens": 0,
                    },
                }),
            ),
        },
        _ => respond(
            &mut stream,
            404,
            &json!({"type": "error", "error": {"type": "not_found_error", "message": "no such route"}}),
        ),
    }
}

/// The request line's path, every header lower-cased, and the body.
fn read_request(stream: &TcpStream) -> Option<(String, BTreeMap<String, String>, String)> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let path = line.split_whitespace().nth(1)?.to_string();
    let mut headers = BTreeMap::new();
    let mut length = 0usize;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).ok()? == 0 {
            break;
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        let Some((name, value)) = header.split_once(':') else {
            continue;
        };
        let (name, value) = (name.trim().to_ascii_lowercase(), value.trim().to_string());
        if name == "content-length" {
            length = value.parse().unwrap_or(0);
        }
        headers.insert(name, value);
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).ok()?;
    Some((path, headers, String::from_utf8_lossy(&body).into_owned()))
}

/// A redirect. `302` is the ordinary one; `307` is the dangerous one,
/// because it replays the POST and its body at the new origin.
fn redirect(stream: &mut TcpStream, status: u16, location: &str) {
    let head = format!(
        "HTTP/1.1 {status} Redirect\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.flush();
}

fn respond(stream: &mut TcpStream, status: u16, body: &Value) {
    let body = body.to_string();
    let head = format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
}

// ------------------------------------------------------------ the fixtures

fn adapter(fake: &Fake) -> AnthropicAdapter {
    AnthropicAdapter::new(SecretString::new(KEY), DEFAULT_MODEL, &fake.base_url)
}

fn adapter_with(fake: &Fake, cfg: AnthropicConfig) -> AnthropicAdapter {
    AnthropicAdapter::with_config(
        SecretString::new(KEY),
        AnthropicConfig {
            base_url: fake.base_url.clone(),
            ..cfg
        },
    )
}

// ------------------------------------------------------- the first-party arch

#[test]
fn complete_concatenates_the_text_blocks_and_sends_the_pinned_request() {
    let fake = Fake::start(Canned::default());
    let answer = adapter(&fake).complete("ROLE: draft\nGOAL: say something", 0);
    let answer = answer.expect("the stand-in answers");
    assert_eq!(answer.text, "the first half and the second");

    let sent = fake.only("/v1/messages");
    // The two headers the API is addressed by, and the key on the header the
    // API reads it from — never a query string, never the body.
    assert_eq!(
        sent.headers.get("anthropic-version").map(String::as_str),
        Some(ANTHROPIC_VERSION),
    );
    assert_eq!(sent.headers.get("x-api-key").map(String::as_str), Some(KEY));
    assert_eq!(
        sent.headers.get("content-type").map(String::as_str),
        Some("application/json"),
    );
    // And the body, exactly as the plan pins it.
    assert_eq!(sent.body["model"], DEFAULT_MODEL);
    assert_eq!(sent.body["thinking"], json!({"type": "adaptive"}));
    assert_eq!(sent.body["max_tokens"], json!(MAX_OUTPUT_TOKENS));
    assert_eq!(
        sent.body["messages"],
        json!([{"role": "user", "content": "ROLE: draft\nGOAL: say something"}]),
    );
    // One request, one answer: there is no caller here to stream to, and the
    // absence of the field is what says so.
    assert!(
        sent.body.get("stream").is_none(),
        "nothing streams: {}",
        sent.body
    );
}

#[test]
fn an_answer_reports_the_measured_prompt_and_the_list_price_from_the_table() {
    let fake = Fake::start(Canned {
        input_tokens: 10_000,
        output_tokens: 2_000,
        ..Default::default()
    });
    let answer = adapter(&fake).complete("hello", 0).expect("answered");
    // The provider counted the prompt; this node only estimated it.
    assert_eq!(answer.tokens_in_measured, Some(10_000));
    // 10 000 × $5/MTok + 2 000 × $25/MTok = $0.05 + $0.05.
    let cost = answer.cost_list_usd.expect("a metered call has a price");
    assert!(
        (cost - 0.10).abs() < 1e-9,
        "opus-5 at 10k in / 2k out is $0.10, not ${cost}"
    );
    let details = answer.details.expect("measurements");
    assert_eq!(details["input_tokens"], 10_000);
    assert_eq!(details["output_tokens"], 2_000);
    assert_eq!(details["stop_reason"], "end_turn");
    assert_eq!(details["message_id"], "msg_01FAKE");
}

#[test]
fn the_pre_check_asks_the_api_to_count_and_refuses_past_the_budget() {
    let fake = Fake::start(Canned {
        // Well past nine tenths of the 1 000-token ceiling below.
        count: Some(5_000),
        ..Default::default()
    });
    let adapter = adapter_with(
        &fake,
        AnthropicConfig {
            context_ceiling: 1_000,
            ..Default::default()
        },
    );
    match adapter.complete("a short prompt the API says is long", 0) {
        Err(AdapterError::I4Prime { needed, ceiling }) => {
            assert_eq!(needed, 5_000);
            // The same number `context_budget` hands the kernel.
            assert_eq!(ceiling, adapter.context_budget());
            assert_eq!(ceiling, 900);
        }
        other => panic!("expected an I4′ refusal, got {other:?}"),
    }
    // Refused *before* anything was sent: the count is the only call made.
    assert_eq!(fake.seen("/v1/messages").len(), 0);
    assert_eq!(fake.seen("/v1/messages/count_tokens").len(), 1);
}

#[test]
fn a_count_that_fails_falls_back_to_the_estimate_rather_than_the_call() {
    let fake = Fake::start(Canned {
        count: None,
        ..Default::default()
    });
    // A 429 on the counter is a hiccup, not a reason to refuse an inference:
    // the estimate stands in and the call goes through.
    let answer = adapter(&fake)
        .complete("hello", 0)
        .expect("answered anyway");
    assert_eq!(answer.text, "the first half and the second");
    assert_eq!(fake.seen("/v1/messages").len(), 1);
}

#[test]
fn the_post_check_refuses_an_answer_whose_measured_prompt_reached_the_ceiling() {
    let fake = Fake::start(Canned {
        // The counter says it fits; the answer says the API read more than
        // the ceiling. The answer is the measurement, so it wins.
        count: Some(10),
        input_tokens: 4_096,
        ..Default::default()
    });
    let adapter = adapter_with(
        &fake,
        AnthropicConfig {
            context_ceiling: 4_096,
            ..Default::default()
        },
    );
    match adapter.complete("short", 0) {
        Err(AdapterError::I4Prime { needed, .. }) => assert_eq!(needed, 4_096),
        other => panic!("expected an I4′ refusal after the call, got {other:?}"),
    }
}

#[test]
fn an_api_error_becomes_other_carrying_the_api_s_message_and_never_the_key() {
    let fake = Fake::start(Canned {
        error: Some((
            400,
            json!({"type": "error", "error": {
                "type": "invalid_request_error",
                "message": "max_tokens: must be less than or equal to 64000",
            }}),
        )),
        ..Default::default()
    });
    let err = adapter(&fake)
        .complete("hello", 0)
        .expect_err("a 400 is a failed call");
    match err {
        AdapterError::Other(e) => {
            let text = format!("{e:#}");
            assert!(
                text.contains("max_tokens: must be less than or equal to 64000"),
                "the API's own message is what the caller needs: {text}"
            );
            assert!(
                text.contains("invalid_request_error"),
                "and its type: {text}"
            );
            assert!(!text.contains(KEY), "the key is in the error: {text}");
            assert!(
                !text.contains("sk-ant"),
                "a key-shaped string leaked: {text}"
            );
        }
        other => panic!("an API error is not an invariant refusal: {other:?}"),
    }
}

#[test]
fn a_refusal_stop_reason_is_a_failed_call_and_not_an_empty_draft() {
    let fake = Fake::start(Canned {
        content: json!([]),
        stop_reason: "refusal".into(),
        ..Default::default()
    });
    let err = adapter(&fake)
        .complete("hello", 0)
        .expect_err("nothing was answered");
    let AdapterError::Other(e) = err else {
        panic!("a refusal is not an I4′ refusal")
    };
    assert!(
        format!("{e:#}").contains("refusal"),
        "say which stop reason: {e:#}"
    );
}

#[test]
fn the_manifest_is_a_us_cloud_arch_kept_thirty_days_at_business_and_ungoverned() {
    let m = AnthropicAdapter::manifest_for(&AnthropicConfig::default());
    assert_eq!(m.name, "anthropic/claude-opus-5");
    assert_eq!(m.locality, Locality::Cloud);
    assert_eq!(m.jurisdiction, "US");
    assert_eq!(m.retention_days, Some(30));
    assert_eq!(m.clearance.max_scope, Scope::Business);
    assert!(!m.clearance.third_party_allowed);
    assert!(!m.governed);
    assert_eq!(m.determinism, Determinism::NonDeterministic);
    assert_eq!(m.identity.engine, "anthropic-api");
    assert_eq!(m.identity.engine_version, ANTHROPIC_VERSION);
    assert_eq!(m.identity.backend, "anthropic-first-party");
    assert_eq!(m.identity.weights_sha256, "model:claude-opus-5");
    // Metered, unlike the subscription arch: a per-token price, in euros.
    // $5/MTok in at the pinned rate is €0.0046 per 1 000 tokens.
    let price = m
        .cost_per_1k_tokens_eur
        .expect("a listed model carries a price");
    assert!((price - 0.0046).abs() < 1e-9, "{price}");
    assert!(m.validate().is_ok());
}

#[test]
fn the_jurisdiction_and_the_host_are_part_of_the_arch_id() {
    let us = AnthropicAdapter::manifest_for(&AnthropicConfig::default());
    let eu = bedrock::manifest_for(&bedrock::BedrockConfig::default());
    assert_ne!(
        us.arch_id(),
        eu.arch_id(),
        "the same model in two jurisdictions is two arches"
    );
    // And the model is too, on either side.
    let sonnet = AnthropicAdapter::manifest_for(&AnthropicConfig {
        model: "claude-sonnet-5".into(),
        ..Default::default()
    });
    assert_ne!(us.arch_id(), sonnet.arch_id());
}

#[test]
fn the_budget_is_nine_tenths_of_the_ceiling_and_is_what_complete_enforces() {
    let fake = Fake::start(Canned::default());
    let a = adapter_with(
        &fake,
        AnthropicConfig {
            context_ceiling: 200_000,
            ..Default::default()
        },
    );
    assert_eq!(a.context_budget(), 180_000);
    assert_eq!(a.manifest().context_ceiling, 200_000);
}

#[test]
fn one_answer_is_bounded_and_never_past_the_api_s_own_cap() {
    let fake = Fake::start(Canned::default());
    // The caller asks for more than the adapter's cap; the cap wins.
    adapter(&fake).complete("hi", 1_000_000).expect("answered");
    assert_eq!(
        fake.only("/v1/messages").body["max_tokens"],
        MAX_OUTPUT_TOKENS
    );
    // And a caller that asks for less than the cap gets what it asked for:
    // `max_tokens` is the caller's bound on this one answer.
    let fake = Fake::start(Canned::default());
    adapter(&fake).complete("hi", 128).expect("answered");
    assert_eq!(fake.only("/v1/messages").body["max_tokens"], 128);
}

#[test]
fn the_estimate_is_three_bytes_a_token_plus_a_fixed_margin() {
    assert_eq!(AnthropicAdapter::estimate_tokens(""), 64);
    assert_eq!(AnthropicAdapter::estimate_tokens(&"x".repeat(300)), 164);
}

// ------------------------------------------------------------- the key itself

#[test]
fn a_secret_never_prints_itself() {
    let key = SecretString::new(KEY);
    assert_eq!(format!("{key:?}"), "SecretString(redacted)");
    // And it can take itself back out of anything about to be printed.
    assert_eq!(
        key.scrub(&format!("Authorization failed for {KEY}")),
        "Authorization failed for [redacted]"
    );
}

#[test]
fn a_mount_spec_for_this_arch_carries_no_key_and_one_that_does_is_refused() {
    // What `arch.mount { kind: "anthropic" }` records: the model and the
    // numbers, and nothing that could be a credential.
    let spec = MountSpec::new(
        "anthropic",
        json!({"model": DEFAULT_MODEL, "max_tokens": 4096, "context_ceiling": 200_000}),
    );
    assert!(spec.is_ok(), "{spec:?}");
    // The guard is what stops a future config from smuggling one in.
    assert!(MountSpec::new("anthropic", json!({"api_key": KEY})).is_err());
}

#[test]
fn a_key_read_from_a_file_is_the_file_s_one_line_and_a_missing_one_says_so() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("key");
    std::fs::write(&path, format!("{KEY}\n")).expect("write");
    let key = vk_arch_anthropic::load_key(&KeySource::File(path), "anthropic").expect("read");
    assert_eq!(key.scrub(KEY), "[redacted]");

    let missing = dir.path().join("nope");
    let err = vk_arch_anthropic::load_key(&KeySource::File(missing), "anthropic")
        .expect_err("no such file");
    let text = format!("{err:#}");
    assert!(
        text.contains("vk secret set anthropic"),
        "say how to fix it: {text}"
    );
}

// --------------------------------------------------------------- EU / Bedrock

#[test]
fn the_bedrock_manifest_is_an_eu_arch_that_keeps_nothing() {
    let m = bedrock::manifest_for(&bedrock::BedrockConfig::default());
    assert_eq!(m.jurisdiction, "EU");
    // AWS prices Bedrock and this node has not read that list, so the arch
    // claims no price at all rather than a misleading zero (Ruling 30).
    assert_eq!(m.cost_per_1k_tokens_eur, None);
    // Bedrock does not retain model inputs or outputs; there is no window to
    // name, which is not the same as a window of unknown length.
    assert_eq!(m.retention_days, None);
    assert_eq!(m.locality, Locality::Cloud);
    assert_eq!(m.clearance.max_scope, Scope::Business);
    assert!(!m.clearance.third_party_allowed);
    assert!(!m.governed);
    assert_eq!(m.identity.engine, "bedrock-converse");
    assert_eq!(m.identity.backend, "aws-bedrock");
    // The region is in the identity: the same model in Frankfurt and in
    // Dublin are two arches, because where the inference happened is part of
    // what the arch is.
    assert_eq!(
        m.identity.sampling.get("region").map(String::as_str),
        Some("eu-central-1")
    );
    let dublin = bedrock::manifest_for(&bedrock::BedrockConfig {
        region: "eu-west-1".into(),
        ..Default::default()
    });
    assert_ne!(m.arch_id(), dublin.arch_id());
    assert!(m.validate().is_ok());
}

#[test]
fn only_an_eu_region_may_carry_the_eu_jurisdiction() {
    assert!(bedrock::check_region("eu-central-1").is_ok());
    assert!(bedrock::check_region("eu-west-1").is_ok());
    let err = bedrock::check_region("us-east-1").expect_err("not the EU");
    assert!(format!("{err:#}").contains("eu-central-1"), "{err:#}");
}

#[test]
fn converse_input_pins_the_message_shape_and_the_bound_on_one_answer() {
    let input = bedrock::converse_input("ROLE: draft\nGOAL: hello", 512);
    assert_eq!(
        input["messages"],
        json!([{"role": "user", "content": [{"text": "ROLE: draft\nGOAL: hello"}]}]),
    );
    assert_eq!(input["inferenceConfig"]["maxTokens"], 512);
    // `0` means "no opinion": the mount's own cap is what goes out.
    let unbounded = bedrock::converse_input("hello", 0);
    assert_eq!(
        unbounded["inferenceConfig"]["maxTokens"],
        json!(MAX_OUTPUT_TOKENS)
    );
    // And the cap is never talked past.
    let greedy = bedrock::converse_input("hello", 1_000_000);
    assert_eq!(
        greedy["inferenceConfig"]["maxTokens"],
        json!(MAX_OUTPUT_TOKENS)
    );
}

#[test]
fn a_bedrock_model_id_keeps_a_full_one_and_prefixes_a_bare_one() {
    // A bare model name is an Anthropic model on Bedrock.
    assert_eq!(
        bedrock::model_id("eu-central-1", "claude-opus-5"),
        "eu.anthropic.claude-opus-5"
    );
    // Anything already qualified is passed through untouched: a caller who
    // names an inference profile means that profile.
    assert_eq!(
        bedrock::model_id("eu-central-1", "anthropic.claude-sonnet-5"),
        "anthropic.claude-sonnet-5"
    );
}

// ------------------------------------------------------------- the model table

#[test]
fn every_model_in_the_table_is_priced_and_has_a_window() {
    for m in vk_arch_anthropic::MODELS {
        assert!(m.context_window > 0, "{}", m.id);
        // Adaptive thinking is a 4.6-and-later parameter; the one
        // 4.5-generation row in the table is the one that must not be sent it.
        assert_eq!(
            m.thinking_supported,
            !m.id.contains("-4-5"),
            "{} has the wrong thinking flag for its generation",
            m.id
        );
        assert!(m.input_usd_per_mtok > 0.0, "{}", m.id);
        assert!(m.output_usd_per_mtok > m.input_usd_per_mtok, "{}", m.id);
        assert!(m.latency_ms_p50 > 0, "{}", m.id);
    }
    // The default is in it, and an unknown model is not invented.
    assert!(vk_arch_anthropic::model(DEFAULT_MODEL).is_some());
    assert!(vk_arch_anthropic::model("claude-imaginary-9").is_none());
}

#[test]
fn an_unknown_model_mounts_with_no_price_rather_than_a_made_up_one() {
    let cfg = AnthropicConfig {
        model: "claude-imaginary-9".into(),
        ..Default::default()
    };
    let m = AnthropicAdapter::manifest_for(&cfg);
    // No row in the table, so no price is claimed and no window is invented:
    // the conservative fallback ceiling is used and `vk top` shows nothing
    // it cannot stand behind.
    // `None`, never `0.0`: zero is a claim that the calls are free, and
    // `vk top` prints `?` for the absence of a claim (Ruling 30).
    assert_eq!(m.cost_per_1k_tokens_eur, None);
    assert_eq!(m.context_ceiling, vk_arch_anthropic::FALLBACK_CONTEXT);
    assert_eq!(
        AnthropicAdapter::cost_list_usd("claude-imaginary-9", 1, 1),
        None
    );
}

// ------------------------------------------------- where the key is sent

/// A redirect is a failed call, not a hop to follow.
///
/// reqwest follows up to ten by default and strips only `authorization`,
/// `cookie`, `cookie2`, `proxy-authorization` and `www-authenticate` on a host
/// change — `x-api-key` is a custom header and is on none of those lists, so
/// without `Policy::none()` this node would hand its key to whatever a `307`
/// named, POST body and all (fix round 1, Important 1). Two stand-ins: the one
/// the adapter is pointed at answers `307` to the other, and the other must
/// never be spoken to at all.
#[test]
fn a_redirect_is_refused_and_the_key_never_reaches_the_second_host() {
    // Both kinds: `302`, the ordinary one, and `307`, which replays the POST
    // and its body at the new origin.
    for status in [302u16, 307] {
        let collector = Fake::start(Canned::default());
        let api = Fake::start(Canned {
            redirect_to: Some((status, collector.base_url.clone())),
            ..Default::default()
        });
        let err = adapter(&api)
            .complete("hello", 0)
            .expect_err("a redirect is not an answer");
        let AdapterError::Other(e) = err else {
            panic!("a redirect is not an invariant refusal")
        };
        let text = format!("{e:#}");
        assert!(
            text.contains(&status.to_string()),
            "say what came back: {text}"
        );
        assert!(!text.contains(KEY), "the key is in the error: {text}");
        // The one that matters: the second host saw nothing at all.
        assert!(
            collector.seen("/v1/messages").is_empty(),
            "{status}: the key was sent to the redirect target"
        );
        assert!(collector.seen("/v1/messages/count_tokens").is_empty());
    }
}

/// The origin is bounded wherever it comes from: `https://` to anywhere, or
/// plaintext to this machine's own loopback and nowhere else. The daemon
/// refuses to accept one from a pipe client at all (see `vk-ipc`'s tests);
/// this is the adapter's own last line, which refuses every call rather than
/// putting the key on a wire it should not be on.
#[test]
fn an_adapter_pointed_at_a_plaintext_host_refuses_every_call() {
    let a = AnthropicAdapter::new(
        SecretString::new(KEY),
        DEFAULT_MODEL,
        "http://collector.example",
    );
    let err = a.complete("hello", 0).expect_err("nowhere to send it");
    let AdapterError::Other(e) = err else {
        panic!("not an invariant refusal")
    };
    let text = format!("{e:#}");
    assert!(text.contains("in the clear"), "{text}");
}

/// Haiku 4.5 is in the table and must be callable: adaptive thinking is a
/// 4.6-and-later parameter and a 4.5-generation model 400s on it, so the
/// block is left out of the request rather than sent and refused at the far
/// end (fix round 1, Important 2).
#[test]
fn the_older_generation_is_sent_no_thinking_block_at_all() {
    let fake = Fake::start(Canned::default());
    adapter_with(
        &fake,
        AnthropicConfig {
            model: "claude-haiku-4-5".into(),
            ..Default::default()
        },
    )
    .complete("hello", 0)
    .expect("answered");
    let sent = fake.only("/v1/messages");
    assert_eq!(sent.body["model"], "claude-haiku-4-5");
    assert!(
        sent.body.get("thinking").is_none(),
        "adaptive thinking would 400 on this model: {}",
        sent.body
    );
    // And the two requests are two arches: a model answering without a
    // thinking block is not the same arch as one answering with it.
    assert_ne!(
        AnthropicAdapter::manifest_for(&AnthropicConfig {
            model: "claude-haiku-4-5".into(),
            ..Default::default()
        })
        .identity
        .sampling["thinking"],
        AnthropicAdapter::manifest_for(&AnthropicConfig::default())
            .identity
            .sampling["thinking"],
    );
}

/// The post-check names the number it compared against. A refusal reading
/// `needed 4096, ceiling 3686` is one no operator can reconcile: the
/// threshold is the full window, so the message says the full window (fix
/// round 1, Minor 1).
#[test]
fn the_post_checks_refusal_names_the_ceiling_it_actually_compared() {
    let fake = Fake::start(Canned {
        count: Some(10),
        input_tokens: 4_096,
        ..Default::default()
    });
    let adapter = adapter_with(
        &fake,
        AnthropicConfig {
            context_ceiling: 4_096,
            ..Default::default()
        },
    );
    match adapter.complete("short", 0) {
        Err(AdapterError::I4Prime { needed, ceiling }) => {
            assert_eq!(needed, 4_096);
            assert_eq!(ceiling, 4_096, "the full window, not nine tenths of it");
            assert_ne!(ceiling, adapter.context_budget());
        }
        other => panic!("expected an I4′ refusal after the call, got {other:?}"),
    }
}

/// A hostile far end that echoes the key into `error.type` gets it scrubbed
/// out of the daemon's message like every other string it sends (fix round 1,
/// Minor 2).
#[test]
fn even_the_error_type_is_scrubbed() {
    let fake = Fake::start(Canned {
        error: Some((
            400,
            json!({"type": "error", "error": {
                "type": format!("leak_{KEY}"),
                "message": "nothing to see",
            }}),
        )),
        ..Default::default()
    });
    let err = adapter(&fake).complete("hello", 0).expect_err("a 400");
    let AdapterError::Other(e) = err else {
        panic!("not an invariant refusal")
    };
    let text = format!("{e:#}");
    assert!(
        !text.contains(KEY),
        "the key came back in error.type: {text}"
    );
    assert!(text.contains("leak_[redacted]"), "{text}");
}
