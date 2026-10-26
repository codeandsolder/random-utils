use std::env;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

const DEFAULT_LISTEN: &str = "127.0.0.1:3915";
const DEFAULT_REMOTE_BASE: &str = "sccache:sccache/rust";
const MAX_HEADER_BYTES: usize = 16 * 1024;
const DEFAULT_MAX_OBJECT_BYTES: u64 = 1024 * 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestHead {
    method: String,
    target: String,
    content_length: u64,
    body_prefix: Vec<u8>,
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn parse_content_length(headers: &str) -> io::Result<u64> {
    for line in headers.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            return value.trim().parse::<u64>().map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid Content-Length: {error}"),
                )
            });
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "Content-Length is required",
    ))
}

fn read_request_head(stream: &mut TcpStream) -> io::Result<RequestHead> {
    let mut bytes = Vec::with_capacity(2048);
    let mut chunk = [0_u8; 2048];
    let header_end = loop {
        if let Some(end) = find_header_end(&bytes) {
            break end;
        }
        if bytes.len() >= MAX_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP header exceeds gateway limit",
            ));
        }
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before HTTP headers completed",
            ));
        }
        if bytes.len().saturating_add(read) > MAX_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP header exceeds gateway limit",
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
    };

    let header_text = std::str::from_utf8(&bytes[..header_end])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let Some(first_line) = header_text.lines().next() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing HTTP request line",
        ));
    };
    let mut request_parts = first_line.split_ascii_whitespace();
    let Some(method) = request_parts.next() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing HTTP method",
        ));
    };
    let Some(target) = request_parts.next() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing HTTP target",
        ));
    };
    let content_length = if method == "PUT" {
        parse_content_length(header_text)?
    } else {
        0
    };

    Ok(RequestHead {
        method: method.to_owned(),
        target: target.to_owned(),
        content_length,
        body_prefix: bytes[header_end..].to_vec(),
    })
}

fn is_lower_hex(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn validate_object_key(key: &str) -> bool {
    let mut parts = key.split('/');
    let Some(first) = parts.next() else {
        return false;
    };
    let Some(second) = parts.next() else {
        return false;
    };
    let Some(third) = parts.next() else {
        return false;
    };
    let Some(hash) = parts.next() else {
        return false;
    };
    if parts.next().is_some()
        || first.len() != 1
        || second.len() != 1
        || third.len() != 1
        || hash.len() != 64
    {
        return false;
    }
    if !is_lower_hex(first) || !is_lower_hex(second) || !is_lower_hex(third) || !is_lower_hex(hash)
    {
        return false;
    }
    let bytes = hash.as_bytes();
    first.as_bytes()[0] == bytes[0]
        && second.as_bytes()[0] == bytes[1]
        && third.as_bytes()[0] == bytes[2]
}

fn object_key_from_target(target: &str) -> Option<&str> {
    let key = target.strip_prefix("/v1/sccache-object/")?;
    validate_object_key(key).then_some(key)
}

fn write_response(stream: &mut TcpStream, status: &str, body: &[u8]) -> io::Result<()> {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn copy_exact_to_writer(
    stream: &mut TcpStream,
    body_prefix: &[u8],
    content_length: u64,
    writer: &mut impl Write,
) -> io::Result<()> {
    let prefix_len = u64::try_from(body_prefix.len())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if prefix_len > content_length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "received more body bytes than Content-Length",
        ));
    }
    writer.write_all(body_prefix)?;
    let mut remaining = content_length - prefix_len;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    while remaining != 0 {
        let limit = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let read = stream.read(&mut buffer[..limit])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "request body ended before Content-Length",
            ));
        }
        writer.write_all(&buffer[..read])?;
        remaining -= u64::try_from(read)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    }
    writer.flush()
}

fn upload_object(
    stream: &mut TcpStream,
    request: &RequestHead,
    object_key: &str,
    remote_base: &str,
) -> io::Result<bool> {
    let destination = format!("{}/{object_key}", remote_base.trim_end_matches('/'));
    let mut child = Command::new("rclone")
        .arg("rcat")
        .arg(destination)
        .arg("--no-check-dest")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    let Some(mut stdin) = child.stdin.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io::Error::other("rclone stdin pipe was not created"));
    };
    if let Err(error) = copy_exact_to_writer(
        stream,
        &request.body_prefix,
        request.content_length,
        &mut stdin,
    ) {
        drop(stdin);
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    drop(stdin);
    Ok(child.wait()?.success())
}

fn handle_connection(
    mut stream: TcpStream,
    remote_base: &str,
    max_object_bytes: u64,
) -> io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let request = match read_request_head(&mut stream) {
        Ok(request) => request,
        Err(error) => {
            write_response(&mut stream, "400 Bad Request", b"bad request\n")?;
            return Err(error);
        }
    };

    if request.method == "GET" && request.target == "/healthz" {
        return write_response(&mut stream, "200 OK", b"ok\n");
    }
    if request.method != "PUT" {
        return write_response(
            &mut stream,
            "405 Method Not Allowed",
            b"method not allowed\n",
        );
    }
    let Some(object_key) = object_key_from_target(&request.target) else {
        return write_response(&mut stream, "404 Not Found", b"not found\n");
    };
    if request.content_length > max_object_bytes {
        return write_response(&mut stream, "413 Content Too Large", b"object too large\n");
    }

    match upload_object(&mut stream, &request, object_key, remote_base) {
        Ok(true) => write_response(&mut stream, "201 Created", b"stored\n"),
        Ok(false) => write_response(&mut stream, "502 Bad Gateway", b"storage write failed\n"),
        Err(error) => {
            let _ = write_response(&mut stream, "502 Bad Gateway", b"storage write failed\n");
            Err(error)
        }
    }
}

fn max_object_bytes() -> io::Result<u64> {
    match env::var("SCCACHE_UPLOAD_GATEWAY_MAX_BYTES") {
        Ok(value) => value.parse::<u64>().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid SCCACHE_UPLOAD_GATEWAY_MAX_BYTES: {error}"),
            )
        }),
        Err(env::VarError::NotPresent) => Ok(DEFAULT_MAX_OBJECT_BYTES),
        Err(error) => Err(io::Error::new(io::ErrorKind::InvalidInput, error)),
    }
}

fn run() -> io::Result<()> {
    let listen =
        env::var("SCCACHE_UPLOAD_GATEWAY_LISTEN").unwrap_or_else(|_| DEFAULT_LISTEN.to_owned());
    let remote_base = env::var("SCCACHE_UPLOAD_GATEWAY_REMOTE_BASE")
        .unwrap_or_else(|_| DEFAULT_REMOTE_BASE.to_owned());
    let max_object_bytes = max_object_bytes()?;
    let listener = TcpListener::bind(&listen)?;
    eprintln!("sccache CI upload gateway listening on {listen}");
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                if let Err(error) = handle_connection(stream, &remote_base, max_object_bytes) {
                    eprintln!("upload gateway request failed: {error}");
                }
            }
            Err(error) => eprintln!("upload gateway accept failed: {error}"),
        }
    }
    Ok(())
}

fn main() -> io::Result<()> {
    run()
}

#[cfg(test)]
mod tests {
    use super::{RequestHead, find_header_end, object_key_from_target, validate_object_key};

    #[test]
    fn finds_header_boundary() {
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n\r\nabc"), Some(18));
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn accepts_only_normalized_lowercase_hash_paths() {
        let hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key = format!("0/1/2/{hash}");
        assert!(validate_object_key(&key));
        assert_eq!(
            object_key_from_target(&format!("/v1/sccache-object/{key}")),
            Some(key.as_str())
        );
        assert!(!validate_object_key(&format!("0/1/3/{hash}")));
        assert!(!validate_object_key(&format!(
            "0/1/2/{}",
            hash.to_uppercase()
        )));
        assert!(!validate_object_key("../bad"));
    }

    #[test]
    fn request_head_is_plain_owned_data() {
        let request = RequestHead {
            method: "PUT".to_owned(),
            target: "/v1/sccache-object/x".to_owned(),
            content_length: 3,
            body_prefix: b"abc".to_vec(),
        };
        assert_eq!(request.content_length, 3);
        assert_eq!(request.body_prefix, b"abc");
    }
}
