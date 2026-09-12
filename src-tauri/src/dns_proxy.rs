use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, RwLock,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, ResponseCode};
use tauri::AppHandle;

use crate::database::{open_database, record_event};

const LISTEN_ADDR_V4: &str = "127.0.0.1:53";
const LISTEN_ADDR_V6: &str = "[::1]:53";
const UPSTREAM_ADDRS: [&str; 2] = ["1.1.1.1:53", "8.8.8.8:53"];
const READ_TIMEOUT: Duration = Duration::from_millis(250);
const CACHE_TTL: Duration = Duration::from_secs(30);

struct ProxyState {
    domains: RwLock<HashSet<String>>,
    cache: Mutex<HashMap<Vec<u8>, (Instant, Vec<u8>)>>,
}

pub struct DnsProxyHandle {
    stop: Option<Arc<AtomicBool>>,
    threads: Vec<JoinHandle<()>>,
}

impl Default for DnsProxyHandle {
    fn default() -> Self {
        Self {
            stop: None,
            threads: Vec::new(),
        }
    }
}

impl DnsProxyHandle {
    pub fn is_running(&self) -> bool {
        self.stop.is_some()
    }

    pub fn start(&mut self, app: AppHandle) -> Result<(), String> {
        if self.is_running() {
            return Ok(());
        }

        let udp_v4 = UdpSocket::bind(LISTEN_ADDR_V4).map_err(|error| {
            format!("Unable to start the DNS proxy on {LISTEN_ADDR_V4}: {error}")
        })?;
        let udp_v6 = UdpSocket::bind(LISTEN_ADDR_V6).map_err(|error| {
            format!("Unable to start the DNS proxy on {LISTEN_ADDR_V6}: {error}")
        })?;
        let tcp_v4 = TcpListener::bind(LISTEN_ADDR_V4)
            .map_err(|error| format!("Unable to start TCP DNS on {LISTEN_ADDR_V4}: {error}"))?;
        let tcp_v6 = TcpListener::bind(LISTEN_ADDR_V6)
            .map_err(|error| format!("Unable to start TCP DNS on {LISTEN_ADDR_V6}: {error}"))?;
        for socket in [&udp_v4, &udp_v6] {
            socket
                .set_read_timeout(Some(READ_TIMEOUT))
                .map_err(|error| format!("Unable to configure the DNS proxy socket: {error}"))?;
        }
        tcp_v4
            .set_nonblocking(true)
            .map_err(|error| format!("Unable to configure TCP DNS: {error}"))?;
        tcp_v6
            .set_nonblocking(true)
            .map_err(|error| format!("Unable to configure TCP DNS: {error}"))?;

        let stop = Arc::new(AtomicBool::new(false));
        let state = Arc::new(ProxyState {
            domains: RwLock::new(load_blocklist(&app)),
            cache: Mutex::new(HashMap::new()),
        });
        let mut threads = Vec::new();
        for socket in [udp_v4, udp_v6] {
            threads.push(spawn_udp(
                socket,
                Arc::clone(&stop),
                Arc::clone(&state),
                app.clone(),
            ));
        }
        for listener in [tcp_v4, tcp_v6] {
            threads.push(spawn_tcp(
                listener,
                Arc::clone(&stop),
                Arc::clone(&state),
                app.clone(),
            ));
        }
        let refresh_stop = Arc::clone(&stop);
        let refresh_state = Arc::clone(&state);
        let refresh_app = app.clone();
        threads.push(thread::spawn(move || {
            while !refresh_stop.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(2));
                if let Ok(mut domains) = refresh_state.domains.write() {
                    *domains = load_blocklist(&refresh_app);
                }
            }
        }));
        self.stop = Some(stop);
        self.threads = threads;
        Ok(())
    }

    pub fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            stop.store(true, Ordering::Relaxed);
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

impl Drop for DnsProxyHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

fn spawn_udp(
    socket: UdpSocket,
    stop: Arc<AtomicBool>,
    state: Arc<ProxyState>,
    app: AppHandle,
) -> JoinHandle<()> {
    thread::spawn(move || run_udp(socket, stop, state, app))
}

fn spawn_tcp(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    state: Arc<ProxyState>,
    app: AppHandle,
) -> JoinHandle<()> {
    thread::spawn(move || run_tcp(listener, stop, state, app))
}

fn run_udp(socket: UdpSocket, stop: Arc<AtomicBool>, state: Arc<ProxyState>, app: AppHandle) {
    let mut packet = [0_u8; 4096];
    while !stop.load(Ordering::Relaxed) {
        let (size, client) = match socket.recv_from(&mut packet) {
            Ok(result) => result,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue
            }
            Err(_) => break,
        };

        let request = match Message::from_vec(&packet[..size]) {
            Ok(message) => message,
            Err(_) => continue,
        };
        let Some(query) = request.queries().first() else {
            continue;
        };
        let domain = query
            .name()
            .to_utf8()
            .trim_end_matches('.')
            .to_ascii_lowercase();

        if let Ok(response) = resolve_query(&packet[..size], &request, &domain, &state, &app) {
            let _ = socket.send_to(&response, client);
        }
    }
}

fn run_tcp(listener: TcpListener, stop: Arc<AtomicBool>, state: Arc<ProxyState>, app: AppHandle) {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let state = Arc::clone(&state);
                let app = app.clone();
                thread::spawn(move || handle_tcp_client(stream, state, app));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(READ_TIMEOUT);
            }
            Err(_) => break,
        }
    }
}

fn handle_tcp_client(mut stream: TcpStream, state: Arc<ProxyState>, app: AppHandle) {
    let mut length = [0_u8; 2];
    if stream.read_exact(&mut length).is_err() {
        return;
    };
    let mut packet = vec![0_u8; usize::from(u16::from_be_bytes(length))];
    if stream.read_exact(&mut packet).is_err() {
        return;
    }
    let Ok(request) = Message::from_vec(&packet) else {
        return;
    };
    let Some(query) = request.queries().first() else {
        return;
    };
    let domain = query
        .name()
        .to_utf8()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if let Ok(response) = resolve_query(&packet, &request, &domain, &state, &app) {
        let length = (response.len() as u16).to_be_bytes();
        let _ = stream.write_all(&length);
        let _ = stream.write_all(&response);
    }
}

fn resolve_query(
    packet: &[u8],
    request: &Message,
    domain: &str,
    state: &ProxyState,
    app: &AppHandle,
) -> Result<Vec<u8>, String> {
    if is_blocked(state, domain) {
        let response = blocked_response(request)?;
        let _ = record_event(
            app,
            "blocked",
            "sinkhole",
            "DNS query blocked",
            Some(domain),
        );
        return Ok(response);
    }

    let key = packet.get(2..).unwrap_or(packet).to_vec();
    if let Ok(mut cache) = state.cache.lock() {
        if let Some((created, cached)) = cache.get(&key) {
            if created.elapsed() < CACHE_TTL {
                let mut response = cached.clone();
                response[..2].copy_from_slice(&packet[..2]);
                let _ = record_event(
                    app,
                    "allowed",
                    "cache",
                    "DNS response served from cache",
                    Some(domain),
                );
                return Ok(response);
            }
            cache.remove(&key);
        }
    }

    let mut response = forward_query(packet)?;
    if response.len() >= 2 {
        response[..2].copy_from_slice(&packet[..2]);
        if let Ok(mut cache) = state.cache.lock() {
            if cache.len() >= 4096 {
                cache.retain(|_, (created, _)| created.elapsed() < CACHE_TTL);
            }
            cache.insert(key, (Instant::now(), response.clone()));
        }
    }
    let _ = record_event(
        app,
        "allowed",
        "forwarded",
        "DNS query forwarded",
        Some(domain),
    );
    Ok(response)
}

fn load_blocklist(app: &AppHandle) -> HashSet<String> {
    let Ok((connection, _)) = open_database(app) else {
        return HashSet::new();
    };
    let Ok(mut statement) =
        connection.prepare("SELECT domain FROM blocked_domains WHERE enabled = 1")
    else {
        return HashSet::new();
    };
    let Ok(rows) = statement.query_map([], |row| row.get::<_, String>(0)) else {
        return HashSet::new();
    };
    rows.flatten()
        .map(|domain| domain.to_ascii_lowercase())
        .collect()
}

fn is_blocked(state: &ProxyState, domain: &str) -> bool {
    let Ok(domains) = state.domains.read() else {
        return false;
    };
    domains
        .iter()
        .any(|blocked| domain_matches(domain, blocked))
}

fn domain_matches(query: &str, blocked: &str) -> bool {
    query == blocked || query.ends_with(&format!(".{blocked}"))
}

fn blocked_response(request: &Message) -> Result<Vec<u8>, String> {
    let mut response = request.clone();
    response.set_message_type(MessageType::Response);
    response.set_response_code(ResponseCode::NXDomain);
    response.set_authoritative(true);
    response.answers_mut().clear();
    response.name_servers_mut().clear();
    response.additionals_mut().clear();
    response
        .to_vec()
        .map_err(|error| format!("Unable to encode DNS response: {error}"))
}

fn forward_query(packet: &[u8]) -> Result<Vec<u8>, String> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|error| format!("Unable to open upstream DNS socket: {error}"))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| format!("Unable to configure upstream DNS socket: {error}"))?;
    let mut last_error = String::from("No upstream DNS server responded.");
    for upstream in UPSTREAM_ADDRS {
        if let Err(error) = socket.send_to(packet, upstream) {
            last_error = error.to_string();
            continue;
        }
        let mut response = [0_u8; 4096];
        match socket.recv_from(&mut response) {
            Ok((size, _source)) => return Ok(response[..size].to_vec()),
            Err(error) => last_error = error.to_string(),
        }
    }
    Err(format!(
        "Unable to receive upstream DNS response: {last_error}"
    ))
}

#[cfg(test)]
mod tests {
    use super::{blocked_response, domain_matches};
    use hickory_proto::op::{Message, ResponseCode};
    #[test]
    fn blocked_response_preserves_query_id_and_returns_nxdomain() {
        let request = Message::from_vec(&[
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'w',
            b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, 0x00, 0x01, 0x00, 0x01,
        ])
        .unwrap();
        let response = Message::from_vec(&blocked_response(&request).unwrap()).unwrap();
        assert_eq!(response.id(), 0x1234);
        assert_eq!(response.response_code(), ResponseCode::NXDomain);
    }

    #[test]
    fn blocked_domains_match_subdomains_without_matching_lookalikes() {
        assert!(domain_matches("ads.example.com", "example.com"));
        assert!(domain_matches("example.com", "example.com"));
        assert!(!domain_matches("notexample.com", "example.com"));
    }
}
