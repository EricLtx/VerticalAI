//! The client side: one connection, one call in flight at a time, a presence
//! proof attached per call (never remembered between calls).
use crate::transport::{self, Endpoint};
use crate::{PresenceProof, Request, Response};
use anyhow::{anyhow, Result};
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines, ReadHalf, WriteHalf};
use tokio::sync::Mutex;

type Stream = Box<dyn transport::Stream>;

struct Conn {
    lines: Lines<BufReader<ReadHalf<Stream>>>,
    w: WriteHalf<Stream>,
}

pub struct Client {
    conn: Mutex<Conn>,
    next_id: AtomicU64,
}

/// The server answered with an error. The code is kept so a caller can tell
/// an invariant refusal from a bad argument without parsing the message.
#[derive(Debug, thiserror::Error)]
#[error("{message} ({code})")]
pub struct CallError {
    pub code: i32,
    pub message: String,
}

impl Client {
    pub async fn connect(ep: &Endpoint) -> Result<Client> {
        let stream = transport::os::connect(ep).await?;
        let (r, w) = tokio::io::split(stream);
        Ok(Client {
            conn: Mutex::new(Conn {
                lines: BufReader::new(r).lines(),
                w,
            }),
            next_id: AtomicU64::new(1),
        })
    }

    pub async fn call(
        &self,
        method: &str,
        params: Value,
        presence: Option<PresenceProof>,
    ) -> Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let req = Request {
            jsonrpc: "2.0".into(),
            id,
            method: method.into(),
            params,
            presence,
        };
        let mut line = serde_json::to_string(&req)?;
        line.push('\n');
        let mut c = self.conn.lock().await;
        c.w.write_all(line.as_bytes()).await?;
        let reply = c
            .lines
            .next_line()
            .await?
            .ok_or_else(|| anyhow!("connection closed"))?;
        let resp: Response = serde_json::from_str(&reply)?;
        match (resp.result, resp.error) {
            (Some(v), None) if resp.id == id => Ok(v),
            (_, Some(e)) => Err(CallError {
                code: e.code,
                message: e.message,
            }
            .into()),
            _ => Err(anyhow!("malformed response to request {id}")),
        }
    }
}
