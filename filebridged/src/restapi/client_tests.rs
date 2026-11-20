//! The Rust client against this server, and against servers that answer what
//! an attacker on the path could answer.

use std::collections::HashMap;
use std::net::SocketAddr;

use axum::Router;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::any;
use filebridge::{Error, FileBridgeClient};

use crate::config::{Config, LocationEntry};

const TOKEN: &str = "secret";

fn location(dir: &std::path::Path, token: Option<&str>) -> LocationEntry {
    LocationEntry {
        name: "testloc".to_string(),
        path: dir.canonicalize().unwrap(),
        allow_read: true,
        allow_create: true,
        allow_replace: true,
        allow_inspect: true,
        allow_delete: true,
        allow_recurse: true,
        allow_mkdir: true,
        token: token.map(str::to_owned),
        #[cfg(unix)]
        file_permissions: None,
        #[cfg(unix)]
        dir_permissions: None,
    }
}

/// Serves `app` on a free local port and returns a client for it.
async fn serve(app: Router) -> FileBridgeClient {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    FileBridgeClient::new(&format!("http://{addr}")).unwrap()
}

/// Serves `dir` as the location `testloc`.
async fn serve_dir(dir: &std::path::Path, token: Option<&str>) -> FileBridgeClient {
    let mut locations = HashMap::new();
    locations.insert("testloc".to_string(), location(dir, token));
    serve(super::routes(Config { locations })).await
}

/// A server that answers every request with `answer`.
async fn serve_fixed<R>(answer: fn(HeaderMap) -> R) -> FileBridgeClient
where
    R: IntoResponse + 'static,
{
    serve(Router::new().fallback(any(
        move |headers: HeaderMap| async move { answer(headers) },
    )))
    .await
}

fn api_error(result: Result<impl std::fmt::Debug, Error>) -> (u16, String) {
    match result {
        Err(Error::Api(status, message)) => (status.as_u16(), message),
        other => panic!("expected an API error, got {other:?}"),
    }
}

fn unverified(result: Result<impl std::fmt::Debug, Error>) -> (u16, String) {
    match result {
        Err(Error::Unverified(status, message)) => (status.as_u16(), message),
        other => panic!("expected an unverified response, got {other:?}"),
    }
}

#[tokio::test]
async fn token_mode_operations() {
    let tmp = tempfile::tempdir().unwrap();
    let client = serve_dir(tmp.path(), Some(TOKEN)).await;
    let loc = client.location("testloc", Some(TOKEN.to_string()));

    // Larger than one stream chunk, so several frames are involved.
    let content: Vec<u8> = (0..150_000u32).map(|i| (i % 251) as u8).collect();

    loc.write("docs/a.bin", &content, None).await.unwrap();
    assert_eq!(
        std::fs::read(tmp.path().join("docs/a.bin")).unwrap(),
        content
    );

    assert_eq!(loc.read("docs/a.bin").await.unwrap(), content);
    assert_eq!(
        loc.read_range("docs/a.bin", 70_000, 10).await.unwrap(),
        &content[70_000..70_010]
    );
    // A range that reaches past the end gives what is there.
    assert_eq!(
        loc.read_range("docs/a.bin", 149_990, 50).await.unwrap(),
        &content[149_990..]
    );
    assert_eq!(
        loc.read_range("docs/a.bin", 200_000, 50).await.unwrap(),
        b""
    );

    let mut streamed = Vec::new();
    loc.read_stream("docs/a.bin", &mut streamed).await.unwrap();
    assert_eq!(streamed, content);

    loc.write_stream("docs/b.bin", std::io::Cursor::new(content.clone()))
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(tmp.path().join("docs/b.bin")).unwrap(),
        content
    );

    let info = loc.info_extensive("docs/a.bin").await.unwrap();
    assert_eq!(info.name, "docs/a.bin");
    assert_eq!(info.size, Some(150_000));
    assert!(info.sha256.is_some());

    let mut names: Vec<String> = loc
        .list(Some("docs"))
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.name)
        .collect();
    names.sort();
    assert_eq!(names, ["a.bin", "b.bin"]);
    assert_eq!(loc.list(None).await.unwrap()[0].name, "docs");

    loc.rename("docs/b.bin", "docs/c.bin").await.unwrap();
    assert!(!tmp.path().join("docs/b.bin").exists());
    assert!(tmp.path().join("docs/c.bin").exists());

    loc.delete("docs/c.bin").await.unwrap();
    assert!(!tmp.path().join("docs/c.bin").exists());

    assert!(loc.permissions().await.unwrap().read);
}

#[tokio::test]
async fn token_mode_errors_keep_status_and_message() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir(tmp.path().join("docs")).unwrap();
    let client = serve_dir(tmp.path(), Some(TOKEN)).await;
    let loc = client.location("testloc", Some(TOKEN.to_string()));

    let not_found = (404, "path not found".to_string());
    assert_eq!(api_error(loc.read("nope.txt").await), not_found);
    assert_eq!(api_error(loc.info("nope.txt").await), not_found);
    assert_eq!(api_error(loc.rename("nope.txt", "b.txt").await), not_found);
    let mut sink = Vec::new();
    assert_eq!(
        api_error(loc.read_stream("nope.txt", &mut sink).await),
        not_found
    );

    assert_eq!(
        api_error(loc.write("../escape.txt", b"x", None).await),
        (403, "invalid path".to_string())
    );

    assert!(matches!(loc.read("docs").await, Err(Error::IsDirectory)));
    assert!(matches!(
        loc.read_stream("docs", &mut sink).await,
        Err(Error::IsDirectory)
    ));
}

#[tokio::test]
async fn wrong_token_is_an_unverified_response() {
    let tmp = tempfile::tempdir().unwrap();
    let client = serve_dir(tmp.path(), Some(TOKEN)).await;
    let loc = client.location("testloc", Some("not-the-token".to_string()));

    assert_eq!(
        unverified(loc.info("a.txt").await),
        (401, "invalid signature".to_string())
    );
    assert_eq!(
        unverified(loc.write("a.txt", b"x", None).await),
        (401, "invalid signature".to_string())
    );
    assert!(!tmp.path().join("a.txt").exists());
}

#[tokio::test]
async fn token_for_a_location_without_one_is_an_unverified_response() {
    let tmp = tempfile::tempdir().unwrap();
    let client = serve_dir(tmp.path(), None).await;
    let loc = client.location("testloc", Some(TOKEN.to_string()));

    let (status, message) = unverified(loc.list(None).await);
    assert_eq!(status, 400);
    assert!(message.contains("has no token"), "{message}");
}

#[tokio::test]
async fn plain_mode_operations() {
    let tmp = tempfile::tempdir().unwrap();
    let client = serve_dir(tmp.path(), None).await;
    let loc = client.location("testloc", None);

    loc.write("a.txt", b"hello", None).await.unwrap();
    assert_eq!(loc.read("a.txt").await.unwrap(), b"hello");
    assert_eq!(loc.read_range("a.txt", 3, 50).await.unwrap(), b"lo");
    assert_eq!(loc.info("a.txt").await.unwrap().size, Some(5));
    assert_eq!(loc.list(None).await.unwrap().len(), 1);

    let mut streamed = Vec::new();
    loc.read_stream("a.txt", &mut streamed).await.unwrap();
    assert_eq!(streamed, b"hello");

    loc.write_stream("b.txt", std::io::Cursor::new(b"stream".to_vec()))
        .await
        .unwrap();
    assert_eq!(std::fs::read(tmp.path().join("b.txt")).unwrap(), b"stream");

    loc.rename("b.txt", "c.txt").await.unwrap();
    loc.delete("c.txt").await.unwrap();
    assert!(loc.permissions().await.unwrap().read);

    assert_eq!(
        api_error(loc.read("nope.txt").await),
        (404, "path not found".to_string())
    );
}

// The servers below answer what somebody on the path between client and
// server could answer without knowing the token.

#[tokio::test]
async fn made_up_success_is_not_accepted() {
    let client = serve_fixed(|headers| {
        // Echo the nonce, which the request shows in plain text.
        let nonce = headers.get("X-Nonce").cloned().unwrap();
        (StatusCode::NO_CONTENT, [("X-Nonce", nonce)])
    })
    .await;
    let loc = client.location("testloc", Some(TOKEN.to_string()));

    assert_eq!(unverified(loc.write("a.txt", b"x", None).await).0, 204);
    assert_eq!(unverified(loc.delete("a.txt").await).0, 204);
    assert_eq!(unverified(loc.rename("a.txt", "b.txt").await).0, 204);
    assert_eq!(
        unverified(
            loc.write_stream("a.txt", std::io::Cursor::new(b"x".to_vec()))
                .await
        )
        .0,
        204
    );
}

#[tokio::test]
async fn made_up_error_is_not_taken_for_the_servers() {
    let client = serve_fixed(|headers| {
        let nonce = headers.get("X-Nonce").cloned().unwrap();
        (
            StatusCode::NOT_FOUND,
            [("X-Nonce", nonce)],
            "path not found",
        )
    })
    .await;
    let loc = client.location("testloc", Some(TOKEN.to_string()));

    // Not `Error::Api(404, _)`, which callers read as "the file is not there".
    assert_eq!(
        unverified(loc.info("a.txt").await),
        (404, "path not found".to_string())
    );
    assert_eq!(unverified(loc.read("a.txt").await).0, 404);
}

#[tokio::test]
async fn reply_of_another_request_is_not_accepted() {
    // A genuine reply, but encrypted for a request with another signature.
    let client = serve_fixed(|headers| {
        let nonce = headers.get("X-Nonce").cloned().unwrap();
        let reply = filebridge::stream::Reply {
            status: 204,
            error: None,
            body: None,
        };
        let body = filebridge::stream::seal_reply(TOKEN, &"ab".repeat(32), &reply).unwrap();
        ([("X-Nonce", nonce)], body)
    })
    .await;
    let loc = client.location("testloc", Some(TOKEN.to_string()));

    assert_eq!(unverified(loc.delete("a.txt").await).0, 200);
}

#[tokio::test]
async fn truncated_stream_is_not_accepted() {
    // Every DATA frame is authentic, but the STOP frame is cut off.
    let client = serve_fixed(|headers| {
        let nonce = headers.get("X-Nonce").cloned().unwrap();
        let signature = headers.get("X-Signature").unwrap().to_str().unwrap();
        let mut aead = filebridge::stream::StreamAead::new(TOKEN, signature).unwrap();
        let mut chunk = b"first half".to_vec();
        aead.encrypt(&mut chunk).unwrap();
        (
            [
                ("X-Nonce", nonce),
                (
                    "Content-Type",
                    "application/vnd.filebridge.stream".parse().unwrap(),
                ),
            ],
            filebridge::stream::encode_data(&chunk),
        )
    })
    .await;
    let loc = client.location("testloc", Some(TOKEN.to_string()));

    let truncated = |result: Result<_, Error>| {
        matches!(
            result,
            Err(Error::Stream(filebridge::stream::StreamError::Truncated))
        )
    };
    assert!(truncated(loc.read("a.txt").await.map(drop)));
    let mut sink = Vec::new();
    assert!(truncated(
        loc.read_stream("a.txt", &mut sink).await.map(drop)
    ));
}

#[tokio::test]
async fn made_up_stream_is_not_taken_for_a_reply() {
    // A stream is only verified when its frames are decrypted. Where a reply
    // is expected, nobody does that.
    let client = serve_fixed(|headers| {
        let nonce = headers.get("X-Nonce").cloned().unwrap();
        (
            [
                ("X-Nonce", nonce),
                (
                    "Content-Type",
                    "application/vnd.filebridge.stream".parse().unwrap(),
                ),
            ],
            filebridge::stream::encode_stop(None),
        )
    })
    .await;
    let loc = client.location("testloc", Some(TOKEN.to_string()));

    assert_eq!(unverified(loc.delete("a.txt").await).0, 200);
    assert_eq!(unverified(loc.write("a.txt", b"x", None).await).0, 200);
    assert_eq!(unverified(loc.info("a.txt").await).0, 200);
    // Read as file content, the made-up stream fails its verification.
    assert!(matches!(loc.read("a.txt").await, Err(Error::Stream(_))));
}

// The servers below know the token. Their replies are authentic, but they are
// not what this version of the server sends.

/// An authentic reply to the request with `headers`.
fn sealed(
    headers: &HeaderMap,
    status: u16,
    body: Option<serde_json::Value>,
) -> impl IntoResponse + use<> {
    let nonce = headers.get("X-Nonce").cloned().unwrap();
    let signature = headers.get("X-Signature").unwrap().to_str().unwrap();
    let reply = filebridge::stream::Reply {
        status,
        error: None,
        body,
    };
    let body = filebridge::stream::seal_reply(TOKEN, signature, &reply).unwrap();
    ([("X-Nonce", nonce)], body)
}

fn protocol_error(result: Result<impl std::fmt::Debug, Error>) -> String {
    match result {
        Err(Error::Protocol(message)) => message,
        other => panic!("expected a protocol error, got {other:?}"),
    }
}

#[tokio::test]
async fn only_a_success_status_is_a_success() {
    let client = serve_fixed(|headers| sealed(&headers, 302, None)).await;
    let loc = client.location("testloc", Some(TOKEN.to_string()));
    assert_eq!(
        protocol_error(loc.delete("a.txt").await),
        "status 302 in the response"
    );
    assert_eq!(
        protocol_error(loc.write("a.txt", b"x", None).await),
        "status 302 in the response"
    );

    // Not a status code at all.
    let client = serve_fixed(|headers| sealed(&headers, 0, None)).await;
    let loc = client.location("testloc", Some(TOKEN.to_string()));
    assert_eq!(
        protocol_error(loc.delete("a.txt").await),
        "status 0 in the response"
    );
}

#[tokio::test]
async fn reply_that_does_not_fit_the_request_is_not_an_api_error() {
    // `Error::Api` is the server's own statement about the operation. A reply
    // the client cannot use is reported as something else.
    let client = serve_fixed(|headers| sealed(&headers, 200, None)).await;
    let loc = client.location("testloc", Some(TOKEN.to_string()));
    assert_eq!(
        protocol_error(loc.info("a.txt").await),
        "no result in the response"
    );

    let client = serve_fixed(|headers| {
        sealed(
            &headers,
            200,
            Some(serde_json::json!({"name": "a.txt", "is_dir": false})),
        )
    })
    .await;
    let loc = client.location("testloc", Some(TOKEN.to_string()));
    assert_eq!(
        protocol_error(loc.read("a.txt").await),
        "metadata in place of file content"
    );
    assert_eq!(
        protocol_error(loc.permissions().await),
        "no permissions in the response"
    );
}
