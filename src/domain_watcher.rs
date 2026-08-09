use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

//////////////////////////////////////////////////////
/// Domain Watcher Module
/// Acts as a middleware proxy to inspect HTTP headers and protect against typo domains
/// Uses heuristic analysis to detect potential phishing attempts
//////////////////////////////////////////////////////

pub fn watch_domains(trusted_domains: Vec<String>, similiarity_threshold: f32, add: SocketAddr) {
    // Placeholder implementation
    println!("Starting domain watcher with the following settings:");
    println!("Trusted Domains: {:?}", trusted_domains);
    println!("Similarity Threshold: {}", similiarity_threshold);

    let listener = TcpListener::bind(add).unwrap();
    println!("Domain watcher listening on {}", add);
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let peer = stream.peer_addr().unwrap();
                println!("Received connection from {}", peer);
                thread::spawn(move || {
                    handle_request(stream);
                });
            }
            Err(e) => {
                eprintln!("Error accepting connection: {}", e);
            }
        }
    }
    println!("Domain watcher stopped.");
}

pub fn handle_request(mut client: TcpStream) -> std::io::Result<()> {
     // Lese initiale Bytes in einen Puffer bis \r\n\r\n oder Limit
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];
    let mut header_end_pos: Option<usize> = None;

    while buf.len() < 16 * 1024 {
        let n = client.read(&mut tmp)?;
        if n == 0 {
            // Client hat Verbindung geschlossen
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);

        if let Some(pos) = find_header_end(&buf) {
            header_end_pos = Some(pos);
            break;
        }
        // Falls Client direkt TLS sendet ohne HTTP-Header, diese Schleife
        // blockiert ggf. — typische Browser warten auf Proxy-Response.
    }

    let read_len = buf.len();
    let header_end = header_end_pos.unwrap_or(read_len);

    // Parse Request-Line
    let header_str = String::from_utf8_lossy(&buf[..header_end]);
    let first_line = header_str.lines().next().unwrap_or_default().to_string();
    println!("Request line: {}", first_line);

    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        return Ok(());
    }

    let method = parts[0];
    if !method.eq_ignore_ascii_case("CONNECT") {
        // MVP: nur CONNECT unterstützen (vereinfachte Pass-Through)
        let body = "<html><body><h1>WebWatcher</h1><p>Only CONNECT supported in this simple proxy.</p></body></html>";
        let resp = format!(
            "HTTP/1.1 501 Not Implemented\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = client.write_all(resp.as_bytes());
        return Ok(());
    }

    let target = parts[1]; // host:port
    println!("CONNECT to {}", target);

    // Verbindungsaufbau zum Ziel
    match TcpStream::connect(target) {
        Ok(mut server) => {
            // Informiere Client, dass Tunnel hergestellt ist
            client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;
            client.flush()?;

            // Falls wir nach den Headern bereits Bytes gelesen haben (leftover), forward diese zuerst
            if header_end < read_len {
                let leftover = &buf[header_end..read_len];
                if !leftover.is_empty() {
                    if let Err(e) = server.write_all(leftover) {
                        eprintln!("Failed to forward leftover to server ({}): {}", target, e);
                        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
                        return Ok(());
                    }
                }
            }

            // Optional: Timeouts
            let _ = client.set_read_timeout(Some(Duration::from_secs(300)));
            let _ = server.set_read_timeout(Some(Duration::from_secs(300)));

            // Klone Streams für bidirektionales Kopieren in zwei Threads
            let mut client_to_server = client.try_clone()?;
            let mut server_to_client = server.try_clone()?;
            let mut server_to_client_clone = server_to_client.try_clone()?;

            // Client -> Server
            let t1 = thread::spawn(move || {
                let res = std::io::copy(&mut client_to_server, &mut server);
                if let Err(e) = &res {
                    eprintln!("client->server copy error: {}", e);
                }
                // Best-effort shutdown
                let _ = server_to_client_clone.shutdown(std::net::Shutdown::Write);
                res
            });

            // Server -> Client
            let mut client_for_recv = client;
            let t2 = thread::spawn(move || {
                let res = std::io::copy(&mut server_to_client, &mut client_for_recv);
                if let Err(e) = &res {
                    eprintln!("server->client copy error: {}", e);
                }
                let _ = client_for_recv.shutdown(std::net::Shutdown::Write);
                res
            });

            // Warte auf Ende beider Richtungen
            let _ = t1.join();
            let _ = t2.join();

            println!("Tunnel closed for {}", target);
        }
        Err(e) => {
            eprintln!("Failed to connect to target {}: {}", target, e);
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
        }
    }

    Ok(())
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    let needle = b"\r\n\r\n";
    buf.windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + needle.len())
}