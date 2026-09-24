//! What the adapter is allowed to read out of `claude -p --output-format json`.
//!
//! The canned objects here are the shape spike 2a recorded from Claude Code
//! 2.1.281 under a claude.ai subscription: `usage.input_tokens` counts the
//! *uncached* prompt tokens alone, the whole prompt is that plus the two cache
//! figures, and `total_cost_usd` is the list-price equivalent of a call the
//! subscription did not bill.
use vk_arch_claude_code::output;

/// One successful call, as the CLI prints it.
fn success() -> String {
    r#"{
      "type": "result",
      "subtype": "success",
      "is_error": false,
      "duration_ms": 9861,
      "duration_api_ms": 6702,
      "ttft_ms": 1204,
      "num_turns": 1,
      "result": "ok",
      "session_id": "0f1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9",
      "total_cost_usd": 0.0148193,
      "usage": {
        "input_tokens": 12,
        "cache_creation_input_tokens": 3421,
        "cache_read_input_tokens": 11002,
        "output_tokens": 517,
        "service_tier": "standard"
      },
      "modelUsage": {
        "claude-sonnet-5": {
          "inputTokens": 12,
          "outputTokens": 517,
          "cacheReadInputTokens": 11002,
          "cacheCreationInputTokens": 3421,
          "costUSD": 0.0148193,
          "contextWindow": 200000,
          "costBasis": "list"
        }
      },
      "permission_denials": []
    }"#
    .to_string()
}

#[test]
fn parse_reads_every_pinned_field() {
    let j = output::parse(&success()).expect("a successful result parses");
    assert_eq!(j.result, "ok");
    assert!(!j.is_error);
    assert_eq!(j.session_id, "0f1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9");
    assert_eq!(j.input_tokens, 12);
    assert_eq!(j.cache_creation_input_tokens, 3421);
    assert_eq!(j.cache_read_input_tokens, 11002);
    assert_eq!(j.output_tokens, 517);
    assert_eq!(j.duration_ms, 9861);
    assert_eq!(j.duration_api_ms, 6702);
    assert!((j.total_cost_usd - 0.0148193).abs() < 1e-9, "{j:?}");
}

/// `usage.input_tokens` is the uncached remainder, never the prompt. Reading it
/// as the prompt would under-report every cached call by an order of magnitude.
#[test]
fn tokens_in_is_the_whole_prompt_not_the_uncached_remainder() {
    let j = output::parse(&success()).expect("parse");
    assert_eq!(j.tokens_in(), 12 + 3421 + 11002);
    assert_ne!(j.tokens_in(), j.input_tokens);
}

#[test]
fn a_failed_run_is_an_error_carrying_what_claude_said() {
    let failed = success()
        .replace("\"is_error\": false", "\"is_error\": true")
        .replace(
            "\"result\": \"ok\"",
            "\"result\": \"Credit balance is too low\"",
        );
    let err = output::parse(&failed).expect_err("is_error must not be handed back as a completion");
    let msg = err.to_string();
    assert!(
        msg.contains("Credit balance is too low"),
        "the refusal must carry what claude said: {msg}"
    );

    // ...and the fields are still readable, for a caller that wants to log them.
    let raw = output::parse_fields(&failed).expect("a failed object still parses");
    assert!(raw.is_error);
    assert!(raw.failed());
    assert_eq!(raw.result, "Credit balance is too low");
}

/// Spike 2a: on an API error `subtype` stays `"success"` and `is_error` can be
/// absent — `api_error_status` is the field that says the call did not happen.
#[test]
fn an_api_error_status_is_a_failure_even_when_is_error_is_absent() {
    let api_error = r#"{
      "type": "result", "subtype": "success",
      "duration_ms": 812, "duration_api_ms": 640, "num_turns": 1,
      "result": "API Error: 529 overloaded_error",
      "api_error_status": 529,
      "terminal_reason": "api_error",
      "session_id": "s-1", "total_cost_usd": 0.0,
      "usage": {"input_tokens": 0, "output_tokens": 0}
    }"#;
    let err = output::parse(api_error).expect_err("an API error is not a completion");
    let msg = err.to_string();
    assert!(msg.contains("529"), "{msg}");
    assert!(msg.contains("overloaded_error"), "{msg}");
}

/// `--max-turns` is enforced by the CLI: it exits 1 with `error_max_turns`.
#[test]
fn a_turn_limit_refusal_names_its_reason() {
    let hit_limit = r#"{
      "type": "result", "subtype": "error_max_turns", "is_error": true,
      "duration_ms": 4100, "duration_api_ms": 3900, "num_turns": 1,
      "result": "", "terminal_reason": "error_max_turns",
      "session_id": "s-2", "total_cost_usd": 0.01,
      "usage": {"input_tokens": 9, "output_tokens": 40}
    }"#;
    let msg = output::parse(hit_limit)
        .expect_err("a turn limit is a refusal")
        .to_string();
    assert!(msg.contains("error_max_turns"), "{msg}");
}

#[test]
fn malformed_output_is_an_error_and_not_an_empty_completion() {
    for bad in [
        "",
        "not json at all",
        "{\"type\":\"result\"",
        // Valid JSON, but not the object this adapter knows how to read.
        "{\"type\":\"result\",\"subtype\":\"success\"}",
        "[]",
    ] {
        match output::parse(bad) {
            Ok(read) => panic!("{bad:?} must be refused, not read as {read:?}"),
            Err(why) => assert!(
                !why.to_string().is_empty(),
                "a refusal has to say something: {bad:?}"
            ),
        }
    }
}
