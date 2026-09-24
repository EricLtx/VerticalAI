//! A stand-in Ollama on loopback, shared by `tests/api.rs` and
//! `tests/proxy.rs`: the five endpoints spike 1a measured, answering exactly
//! what the real 0.33.3 answered — including the 404 on `/api/tokenize` — and
//! writing down every request it was sent.
//!
//! Plain `std::net` rather than a web framework: the same shape of fake also
//! has to run inside `vk-cli`'s smoke test against a real daemon, and a
//! hand-written HTTP/1.1 responder is both shorter than the dependency and
//! exactly as good at pinning a JSON shape.
//!
//! Each test binary that includes this module uses a part of it, so the parts
//! the other one uses would read as dead code here.
#![allow(dead_code)]

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// What the stand-in answers with. The defaults are spike 1a's measurements
/// for `gemma3:1b` on Ollama 0.33.3, including the 404 on `/api/tokenize`.
#[derive(Debug, Clone)]
pub struct Canned {
    pub version: String,
    /// The tags the server admits to having, with their digests.
    pub models: BTreeMap<String, String>,
    pub family: String,
    pub parameter_size: String,
    pub quantization: String,
    pub context_length: u32,
    /// Does `/api/tokenize` exist? False on 0.33.3, which 404s.
    pub tokenize: bool,
    /// What `/api/chat` reports having read of the prompt. `None` means "the
    /// real count of what the fake tokenizer makes of it".
    pub prompt_eval_count: Option<u32>,
    pub reply: String,
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
pub const PULLED_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";

/// Every request the stand-in was sent, in order: the path and the body.
type Log = Arc<Mutex<Vec<(String, Value)>>>;

pub struct Fake {
    pub base_url: String,
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
    pub fn start(canned: Canned) -> Fake {
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
    pub fn calls(&self, path: &str) -> Vec<Value> {
        self.log
            .lock()
            .expect("log")
            .iter()
            .filter(|(p, _)| p == path)
            .map(|(_, b)| b.clone())
            .collect()
    }

    pub fn pulls(&self) -> Vec<String> {
        self.pulled.lock().expect("pulled").clone()
    }
}

/// How the stand-in counts tokens: whitespace-separated words, with trailing
/// punctuation counting for one more. Close enough to a real tokenizer for
/// `estimate_tokens` to be measured against.
pub fn fake_tokens(text: &str) -> usize {
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
