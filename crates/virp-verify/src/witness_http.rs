//! A minimal HTTP/1.1 GET over `std::net::TcpStream`, for `--witness-url`.
//!
//! This is the ONLY code in `virp-verify` that opens a socket, and it runs
//! only when the examiner passes `--witness-url`. Everything else — every
//! hash, every signature, every proof, including the carried inclusion proof
//! that produces `witness: VERIFIED` — is computed offline from the bundle
//! and the examiner's own key files. A verifier that had to phone anybody to
//! reach a verdict would have made the verdict depend on whoever answered.
//!
//! # Plain HTTP only, and why that is a limit rather than an oversight
//!
//! There is no TLS here. Adding it means adding a TLS stack to a dependency
//! set that is deliberately closed — this binary's entire tree is
//! `docket-bundle`, and the release build is a reproducible static musl
//! artifact whose whole claim is that a reader can rebuild it. The witness
//! client takes exactly the same position for exactly the same reason
//! (`~/virp-witness/crates/witness-client/src/http.rs`).
//!
//! Transport confidentiality is not what makes this check worth anything. A
//! signed tree head is a detached Ed25519 signature over canonical bytes,
//! checked here under a key the examiner supplied out of band. Someone on the
//! path can drop the response or delay it — both of which show up as
//! `witness_consistency: UNVERIFIABLE` with the reason — and cannot forge
//! one. Nothing about the trust decision passes over this socket.
//!
//! For an https witness, point `--witness-url` at a local terminator or an
//! ssh tunnel, which is how the node deployment already reaches one
//! (`~/virp-witness/deploy/node/virp-witness-submit.service`).

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Whole-request ceiling. A witness that has not answered a proof query in
/// this long is a witness that did not answer.
const TIMEOUT: Duration = Duration::from_secs(20);

/// A witness answers with a tree head or a proof — hundreds of bytes, or a
/// few kilobytes for a very large log. Reading unbounded would let a hostile
/// endpoint spend this process's memory to avoid answering a question.
const MAX_RESPONSE: usize = 1 << 20;

/// Fetch `base + path`, returning the response body on 200.
///
/// Every failure is a `String` the caller reports verbatim as the reason a
/// check did not run. There is no retry: a verifier that retried would be
/// deciding on the examiner's behalf how long to wait for evidence.
pub fn get(base: &str, path: &str) -> Result<String, String> {
    let url = join(base, path);
    let (host, port, req_path) = split(&url)?;

    let addr = format!("{host}:{port}");
    let target = addr
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {addr}: {e}"))?
        .next()
        .ok_or_else(|| format!("{addr} resolved to no address"))?;

    let mut stream = TcpStream::connect_timeout(&target, TIMEOUT).map_err(|e| format!("cannot reach {addr}: {e}"))?;
    stream.set_read_timeout(Some(TIMEOUT)).map_err(|e| e.to_string())?;
    stream.set_write_timeout(Some(TIMEOUT)).map_err(|e| e.to_string())?;

    let request = format!(
        "GET {req_path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: virp-verify\r\nAccept: application/json\r\n\
         Connection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("{addr}: {e}"))?;

    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = stream.read(&mut buf).map_err(|e| format!("{addr}: {e}"))?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
        if raw.len() > MAX_RESPONSE {
            return Err(format!("{addr}: response exceeds {MAX_RESPONSE} bytes"));
        }
    }

    let text = String::from_utf8(raw).map_err(|_| format!("{addr}: response is not UTF-8"))?;
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| format!("{addr}: malformed HTTP response (no header/body split)"))?;
    let status_line = head.lines().next().unwrap_or_default();
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| format!("{addr}: malformed status line {status_line:?}"))?;
    if status != 200 {
        return Err(format!(
            "{url} answered {status}: {}",
            body.trim().chars().take(200).collect::<String>()
        ));
    }
    // The witness sends `Content-Length` and closes; no chunked encoding to
    // decode. If that ever changes, this is where it would show up — as a
    // body that will not parse, reported as the reason rather than guessed at.
    Ok(body.to_owned())
}

fn join(base: &str, path: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), path)
}

/// `http://host[:port]/path` split into what a request needs.
fn split(url: &str) -> Result<(String, u16, String), String> {
    if url.starts_with("https://") {
        return Err(format!(
            "{url}: virp-verify speaks plain HTTP only — it carries no TLS stack, by the same rule that keeps \
             its dependency tree closed and its release build reproducible. Point --witness-url at a local \
             terminator or tunnel"
        ));
    }
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("{url}: expected an http:// URL"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(format!("{url}: no host"));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_owned(),
            p.parse::<u16>().map_err(|_| format!("{url}: bad port {p:?}"))?,
        ),
        None => (authority.to_owned(), 80),
    };
    Ok((host, port, path.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_a_plain_url() {
        assert_eq!(
            split("http://127.0.0.1:8790/v1/sth").unwrap(),
            ("127.0.0.1".to_owned(), 8790, "/v1/sth".to_owned())
        );
        assert_eq!(
            split("http://witness.example/v1/sth").unwrap(),
            ("witness.example".to_owned(), 80, "/v1/sth".to_owned())
        );
    }

    #[test]
    fn refuses_https_with_the_reason() {
        let e = split("https://witness.example/v1/sth").unwrap_err();
        assert!(e.contains("plain HTTP only"), "{e}");
    }

    #[test]
    fn joins_without_doubling_the_slash() {
        assert_eq!(join("http://h:1/", "/v1/sth"), "http://h:1/v1/sth");
        assert_eq!(join("http://h:1", "/v1/sth"), "http://h:1/v1/sth");
    }
}
