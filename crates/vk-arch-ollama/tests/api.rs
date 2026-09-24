//! The adapter against a stand-in Ollama: a loopback HTTP server this test
//! starts, which answers the five endpoints spike 1a measured and writes down
//! every request it was sent.
//!
//! What it pins is the half of the adapter no canned-JSON test can reach: that
//! the request actually put on the wire is the one spike 1a measured — no
//! streaming, no thinking, the `num_ctx` and `seed` this arch's identity names
//! — that a prompt the model would silently truncate is refused *before* the
//! server is called at all, that a server which truncated anyway is caught
//! afterwards from its own `prompt_eval_count`, and that the usage on the
//! completion is the server's measurement rather than this node's estimate.
//!
//! The stand-in is plain `std::net` rather than a web framework: the same
//! fake has to run inside `vk-cli`'s smoke test against a real daemon, and a
//! hand-written HTTP/1.1 responder is both shorter than the dependency and
//! exactly as good at pinning a JSON shape.
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use vk_arch_ollama::{ModelIdentity, OllamaAdapter, OllamaConfig};
use vk_kernel::arch::{AdapterError, ArchAdapter};

/// What the stand-in answers with. The defaults are spike 1a's measurements
/// for `gemma3:1b` on Ollama 0.33.3, including the 404 on `/api/tokenize`.
#[derive(Debug, Clone)]
struct Canned {
    version: String,
    /// The tags the server admits to having, with their digests.
    models: BTreeMap<String, String>,
    family: String,
    parameter_size: String,
    quantization: String,
    context_length: u32,
    /// Does `/api/tokenize` exist? False on 0.33.3, which 404s.
    tokenize: bool,
    /// What `/api/chat` reports having read of the prompt. `None` means "the
    /// real count of what the fake tokenizer makes of it".
    prompt_eval_count: Option<u32>,
    reply: String,
}

impl Default for Canned {
    fn default() -> Canned {
        Canned {
            version: "0.33.3".into(),
            models: [(
                "gemma3:1b".to_string(),
                "8648f39daa8fbf5b18c7b4e6a8fb4990c692751d49917417b8842ca5758e7ffc".to_string(),
            )]
            .into_iter()
            .collect(),
            family: "gemma3".into(),
            parameter_size: "999.89M".into(),
            quantization: "Q4_K_M".into(),
            context_length: 32768,
            tokenize: false,
            prompt_eval_count: None,
            reply: "ok".into(),
        }
    }
}

/// The digest the stand-in gives a tag it was made to pull.
const PULLED_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";

/// Every request the stand-in was sent, in order: the path and the body.
type Log = Arc<Mutex<Vec<(String, Value)>>>;

struct Fake {
    base_url: String,
    log: Log,
    /// Models the server was told to pull, which it then has.
    pulled: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
}

impl Drop for Fake {
    fn drop(&mut self) {
        // The serving thread is blocked in `accept`; the flag alone would not
        // wake it, so one connection is made to let it look at the flag and
        // leave. Nothing is joined: a test that fails must not also hang.
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.base_url.trim_start_matches("http://"));
    }
}

impl Fake {
    fn start(canned: Canned) -> Fake {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let base_url = format!("http://{}", listener.local_addr().expect("addr"));
        let log: Log = Arc::default();
        let pulled: Arc<Mutex<Vec<String>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let (l, p, s) = (log.clone(), pulled.clone(), stop.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if s.load(Ordering::SeqCst) {
                    return;
                }
                if let Ok(stream) = stream {
                    serve(stream, &canned, &l, &p);
                }
            }
        });
        Fake {
            base_url,
            log,
            pulled,
            stop,
        }
    }

    /// Every request to `path`, in order.
    fn calls(&self, path: &str) -> Vec<Value> {
        self.log
            .lock()
            .expect("log")
            .iter()
            .filter(|(p, _)| p == path)
            .map(|(_, b)| b.clone())
            .collect()
    }

    fn pulls(&self) -> Vec<String> {
        self.pulled.lock().expect("pulled").clone()
    }
}

/// How the stand-in counts tokens: whitespace-separated words, with trailing
/// punctuation counting for one more. Close enough to a real tokenizer for
/// `estimate_tokens` to be measured against.
fn fake_tokens(text: &str) -> usize {
    text.split_whitespace()
        .map(|w| 1 + usize::from(w.ends_with([',', '.', ';', ':', '?', '!'])))
        .sum()
}

fn serve(mut stream: TcpStream, canned: &Canned, log: &Log, pulled: &Arc<Mutex<Vec<String>>>) {
    let Some((path, body)) = read_request(&stream) else {
        return;
    };
    let parsed: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    log.lock()
        .expect("log")
        .push((path.clone(), parsed.clone()));
    let has = |m: &str| {
        canned.models.contains_key(m) || pulled.lock().expect("pulled").iter().any(|p| p == m)
    };
    let model = parsed["model"].as_str().unwrap_or_default().to_string();
    match path.as_str() {
        "/api/version" => ok(&mut stream, &json!({ "version": canned.version })),
        "/api/tags" => {
            // Whatever it was born with, plus whatever it has been made to
            // pull since: a tag that was pulled is a tag the server has.
            let mut models: BTreeMap<String, String> = canned.models.clone();
            for name in pulled.lock().expect("pulled").iter() {
                models.insert(name.clone(), PULLED_DIGEST.to_string());
            }
            let models: Vec<Value> = models
                .iter()
                .map(|(name, digest)| {
                    json!({
                        "name": name,
                        "model": name,
                        "digest": digest,
                        "size": 815_000_000u64,
                        "details": {
                            "family": canned.family,
                            "parameter_size": canned.parameter_size,
                            "quantization_level": canned.quantization,
                        },
                    })
                })
                .collect();
            ok(&mut stream, &json!({ "models": models }));
        }
        // A pull names its model `name`, not `model`, as every other call
        // does — the stand-in reads the field the real API reads.
        "/api/pull" => {
            let name = parsed["name"].as_str().unwrap_or_default().to_string();
            pulled.lock().expect("pulled").push(name);
            ok(&mut stream, &json!({ "status": "success" }));
        }
        "/api/show" if !has(&model) => {
            fail(
                &mut stream,
                "404 Not Found",
                &json!({ "error": "model not found" }),
            );
        }
        "/api/show" => ok(
            &mut stream,
            &json!({
                "details": {
                    "family": canned.family,
                    "parameter_size": canned.parameter_size,
                    "quantization_level": canned.quantization,
                },
                "model_info": {
                    format!("{}.context_length", canned.family): canned.context_length,
                    format!("{}.embedding_length", canned.family): 1152,
                },
                "capabilities": ["completion", "tools"],
            }),
        ),
        // 0.33.3 has no tokenizer endpoint at all, and says so in plain text.
        "/api/tokenize" if !canned.tokenize => {
            text(&mut stream, "404 Not Found", "404 page not found")
        }
        "/api/tokenize" => {
            let n = fake_tokens(parsed["prompt"].as_str().unwrap_or_default());
            ok(
                &mut stream,
                &json!({ "tokens": (0..n).map(|i| i as i64).collect::<Vec<_>>() }),
            );
        }
        "/api/chat" => {
            let prompt: String = parsed["messages"]
                .as_array()
                .map(|ms| {
                    ms.iter()
                        .filter_map(|m| m["content"].as_str())
                        .collect::<Vec<_>>()
                        .join("\n")
                })
                .unwrap_or_default();
            let counted = u32::try_from(fake_tokens(&prompt)).unwrap_or(u32::MAX);
            ok(
                &mut stream,
                &json!({
                    "model": model,
                    "created_at": "2026-09-24T10:00:00.000000000Z",
                    "message": { "role": "assistant", "content": canned.reply },
                    "done": true,
                    "done_reason": "stop",
                    "total_duration": 1_500_000_000u64,
                    "load_duration": 250_000_000u64,
                    "prompt_eval_count": canned.prompt_eval_count.unwrap_or(counted),
                    "prompt_eval_duration": 120_000_000u64,
                    "eval_count": 5,
                    "eval_duration": 900_000_000u64,
                }),
            );
        }
        _ => fail(
            &mut stream,
            "404 Not Found",
            &json!({ "error": "no such route" }),
        ),
    }
}

/// The request line's path and the body, as far as this stand-in cares.
fn read_request(stream: &TcpStream) -> Option<(String, String)> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let path = line.split_whitespace().nth(1)?.to_string();
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
        if let Some(v) = header
            .to_ascii_lowercase()
            .strip_prefix("content-length:")
            .map(str::trim)
            .and_then(|v| v.parse::<usize>().ok())
        {
            length = v;
        }
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).ok()?;
    Some((path, String::from_utf8_lossy(&body).into_owned()))
}

fn ok(stream: &mut TcpStream, body: &Value) {
    respond(stream, "200 OK", "application/json", &body.to_string());
}

fn fail(stream: &mut TcpStream, status: &str, body: &Value) {
    respond(stream, status, "application/json", &body.to_string());
}

fn text(stream: &mut TcpStream, status: &str, body: &str) {
    respond(stream, status, "text/plain", body);
}

fn respond(stream: &mut TcpStream, status: &str, kind: &str, body: &str) {
    let head = format!(
        "HTTP/1.1 {status}\r\ncontent-type: {kind}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
}

/// A config pointing at the stand-in: no container, so nothing here needs
/// Docker, and `governed` is false for the same reason.
fn config(fake: &Fake, model: &str, num_ctx: u32) -> OllamaConfig {
    OllamaConfig {
        base_url: fake.base_url.clone(),
        model: model.into(),
        num_ctx,
        ..Default::default()
    }
}

fn identity() -> ModelIdentity {
    ModelIdentity {
        digest: "8648f39daa8fbf5b18c7b4e6a8fb4990c692751d49917417b8842ca5758e7ffc".into(),
        family: "gemma3".into(),
        parameter_size: "999.89M".into(),
        quantization: "Q4_K_M".into(),
        context_length: 32768,
    }
}

#[test]
fn chat_request_pins_num_ctx_seed_no_streaming_and_no_thinking() {
    let cfg = OllamaConfig {
        model: "gemma4:e4b".into(),
        num_ctx: 8192,
        seed: 7,
        ..Default::default()
    };
    let wire = serde_json::to_string(&OllamaAdapter::chat_request(&cfg, "hello")).expect("json");
    for pinned in [
        r#""stream":false"#,
        r#""think":false"#,
        r#""num_ctx":8192"#,
        r#""seed":7"#,
        r#""role":"user""#,
        r#""content":"hello""#,
    ] {
        assert!(wire.contains(pinned), "{pinned} missing from {wire}");
    }
}

#[test]
fn manifest_identity_changes_with_digest_num_ctx_or_seed() {
    let cfg = OllamaConfig {
        model: "gemma3:1b".into(),
        num_ctx: 8192,
        seed: 7,
        ..Default::default()
    };
    let base = OllamaAdapter::manifest_for(&cfg, &identity(), "0.33.3", true);

    // The ceiling is half of the smaller of the two windows: spike 1a measured
    // Ollama silently cutting a prompt to `num_ctx / 2 + 3`.
    assert_eq!(base.context_ceiling, 4096);
    assert_eq!(
        OllamaAdapter::manifest_for(
            &OllamaConfig {
                num_ctx: 131_072,
                ..cfg.clone()
            },
            &identity(),
            "0.33.3",
            true
        )
        .context_ceiling,
        32768 / 2,
        "a num_ctx past the model's own window does not widen it"
    );

    let other_digest = OllamaAdapter::manifest_for(
        &cfg,
        &ModelIdentity {
            digest: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            ..identity()
        },
        "0.33.3",
        true,
    );
    let other_ctx = OllamaAdapter::manifest_for(
        &OllamaConfig {
            num_ctx: 4096,
            ..cfg.clone()
        },
        &identity(),
        "0.33.3",
        true,
    );
    let other_seed = OllamaAdapter::manifest_for(
        &OllamaConfig {
            seed: 8,
            ..cfg.clone()
        },
        &identity(),
        "0.33.3",
        true,
    );
    let other_version = OllamaAdapter::manifest_for(&cfg, &identity(), "0.34.3", true);
    let ids: Vec<String> = [
        &base,
        &other_digest,
        &other_ctx,
        &other_seed,
        &other_version,
    ]
    .iter()
    .map(|m| m.arch_id())
    .collect();
    for (i, a) in ids.iter().enumerate() {
        for b in ids.iter().skip(i + 1) {
            assert_ne!(a, b, "two of these manifests share an arch id: {ids:?}");
        }
    }
    assert_eq!(
        base.arch_id(),
        OllamaAdapter::manifest_for(&cfg, &identity(), "0.33.3", true).arch_id(),
        "the same configuration is the same arch"
    );

    // `governed` is the caller's to say — the kernel only contains a process
    // it started under caps — and it is on the manifest either way.
    assert!(base.governed);
    assert!(!OllamaAdapter::manifest_for(&cfg, &identity(), "0.33.3", false).governed);
}

#[test]
fn refuses_a_prompt_the_model_would_truncate() {
    let fake = Fake::start(Canned::default());
    let adapter = OllamaAdapter::mount(config(&fake, "gemma3:1b", 8192)).expect("mount");

    // min(8192, 32768) / 2 = 4096, less the tenth the estimate may be wrong by.
    let ceiling = adapter.manifest().context_ceiling;
    assert_eq!(ceiling, 4096);
    assert_eq!(adapter.context_budget(), 3686);

    // A prompt whose estimate is 0.95 of the ceiling: under it, over the
    // budget, and exactly the prompt Ollama would have cut in half in silence.
    let prompt = "x".repeat(((f64::from(ceiling) * 0.95) as usize - 64) * 3);
    let needed = OllamaAdapter::estimate_tokens(&prompt);
    assert!(needed < ceiling && needed > adapter.context_budget());

    match adapter.complete(&prompt, 256) {
        Err(AdapterError::I4Prime {
            needed: n,
            ceiling: c,
        }) => {
            assert_eq!(n, needed);
            assert_eq!(
                c,
                adapter.context_budget(),
                "the refusal and the budget are one number"
            );
        }
        other => panic!("expected an I4' refusal, got {other:?}"),
    }
    assert!(
        fake.calls("/api/chat").is_empty(),
        "the refusal must happen before the model is called"
    );
}

#[test]
fn fails_when_the_server_reports_a_truncated_prompt() {
    // The server claims to have read `num_ctx / 2 + 3` tokens of the prompt —
    // spike 1a's signature of a silent truncation, with HTTP 200 and
    // `done_reason: "stop"` over the top of it.
    let fake = Fake::start(Canned {
        prompt_eval_count: Some(8192 / 2 + 3),
        ..Default::default()
    });
    let adapter = OllamaAdapter::mount(config(&fake, "gemma3:1b", 8192)).expect("mount");
    match adapter.complete("a short prompt", 256) {
        Err(AdapterError::I4Prime { needed, .. }) => assert_eq!(needed, 4099),
        other => panic!("expected an I4' refusal, got {other:?}"),
    }
    assert_eq!(fake.calls("/api/chat").len(), 1, "the call did happen");
}

#[test]
fn estimate_is_conservative() {
    // A stand-in that *does* tokenize, so the estimate can be measured against
    // a count rather than against another guess.
    let fake = Fake::start(Canned {
        tokenize: true,
        ..Default::default()
    });
    let adapter = OllamaAdapter::mount(config(&fake, "gemma3:1b", 8192)).expect("mount");
    let sentences = [
        "The kernel refuses a prompt it cannot honestly fit.",
        "Ollama truncates an oversize prompt without saying so.",
        "A governed arch is one this node started and capped.",
        "Every mount writes the model digest into the arch id.",
        "The ledger records what was sent before it is sent.",
        "A local model bills nothing and leaks nothing.",
        "Half the window is all the server will really read.",
        "The estimate is three bytes to the token, plus a margin.",
        "A container without caps is not a governor.",
        "Measured usage beats an estimate of the same thing.",
        "The seed is part of what makes this arch this arch.",
        "Thinking is off, so the answer is in the content.",
        "Streaming is off, so one request is one answer.",
        "The digest comes from the tag list, not from the name.",
        "A pull at mount time is not a pull at call time.",
        "Docker Desktop must be running for a container arch.",
        "The volume keeps the weights between runs.",
        "An external server is not governed, and says so.",
        "The context ceiling is measured, not advertised.",
        "Refusing is better than sending half a prompt.",
    ];
    for s in sentences {
        let counted = adapter.count_tokens(s);
        let estimated = OllamaAdapter::estimate_tokens(s);
        assert!(
            f64::from(estimated) >= 1.2 * f64::from(counted),
            "estimate {estimated} is not conservative against {counted} for {s:?}"
        );
    }
    assert_eq!(
        fake.calls("/api/tokenize").len(),
        sentences.len() + 1,
        "one probe at mount, then one count per sentence"
    );
}

#[test]
fn usage_is_measured_not_guessed() {
    let fake = Fake::start(Canned {
        prompt_eval_count: Some(311),
        reply: "the stand-in's answer".into(),
        ..Default::default()
    });
    let adapter = OllamaAdapter::mount(config(&fake, "gemma3:1b", 8192)).expect("mount");
    let out = adapter
        .complete("say something", 256)
        .expect("a completion");
    assert_eq!(out.text, "the stand-in's answer");
    assert_eq!(
        out.tokens_in_measured,
        Some(311),
        "the server counted the prompt; the estimate was only a stand-in for it"
    );
    assert_eq!(
        out.cost_list_usd, None,
        "a model on this machine has no list price"
    );
    let details = out
        .details
        .expect("a local call still reports its own numbers");
    assert_eq!(details["prompt_eval_count"], 311);
    assert_eq!(details["eval_count"], 5);
    assert_eq!(details["eval_duration_ns"], 900_000_000u64);
    assert_eq!(details["load_duration_ns"], 250_000_000u64);
    assert_eq!(details["done_reason"], "stop");
}

#[test]
fn mount_pulls_a_model_the_server_does_not_have_and_leaves_one_it_does() {
    let fake = Fake::start(Canned::default());
    let adapter = OllamaAdapter::mount(config(&fake, "gemma3:1b", 8192)).expect("mount");
    assert!(fake.pulls().is_empty(), "the server already had that tag");
    assert_eq!(
        adapter.manifest().identity.weights_sha256,
        "sha256:8648f39daa8fbf5b18c7b4e6a8fb4990c692751d49917417b8842ca5758e7ffc",
        "the arch is addressed by the weights, not by the tag"
    );
    assert_eq!(adapter.manifest().name, "ollama/gemma3:1b");
    assert_eq!(adapter.manifest().identity.engine_version, "0.33.3");
    assert!(
        !adapter.manifest().governed,
        "no container was asked for, so nothing here is contained"
    );

    let other = Fake::start(Canned::default());
    let pulled = OllamaAdapter::mount(config(&other, "gemma3:270m", 8192))
        .expect("a tag the server does not have is pulled, once, at mount");
    assert_eq!(other.pulls(), vec!["gemma3:270m"]);
    assert_eq!(
        pulled.manifest().identity.weights_sha256,
        format!("sha256:{PULLED_DIGEST}"),
        "the digest is read back after the pull, not assumed before it"
    );
}
