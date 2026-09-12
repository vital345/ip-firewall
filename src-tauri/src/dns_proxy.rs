use std::net::{SocketAddr, UdpSocket};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, ResponseCode};
use tauri::AppHandle;

use crate::database::{open_database, record_event};

const LISTEN_ADDR: &str = "127.0.0.1:53";
const UPSTREAM_ADDR: &str = "1.1.1.1:53";
const READ_TIMEOUT: Duration = Duration::from_millis(250);

pub struct DnsProxyHandle {
    stop: Option<Arc<AtomicBool>>,
    thread: Option<JoinHandle<()>>,
}

impl Default for DnsProxyHandle {
    fn default() -> Self {
        Self {
            stop: None,
            thread: None,
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

        let socket = UdpSocket::bind(LISTEN_ADDR)
            .map_err(|error| format!("Unable to start the DNS proxy on {LISTEN_ADDR}: {error}"))?;
        socket
            .set_read_timeout(Some(READ_TIMEOUT))
            .map_err(|error| format!("Unable to configure the DNS proxy socket: {error}"))?;

        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || run_proxy(socket, thread_stop, app));
        self.stop = Some(stop);
        self.thread = Some(thread);
        Ok(())
    }

    pub fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            stop.store(true, Ordering::Relaxed);
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for DnsProxyHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

fn run_proxy(socket: UdpSocket, stop: Arc<AtomicBool>, app: AppHandle) {
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

        if is_blocked(&app, &domain) {
            if let Ok(response) = blocked_response(&request) {
                let _ = socket.send_to(&response, client);
                let _ = record_event(
                    &app,
                    "blocked",
                    "sinkhole",
                    "DNS query blocked",
                    Some(&domain),
                );
            }
            continue;
        }

        match forward_query(&packet[..size]) {
            Ok(response) => {
                let _ = socket.send_to(&response, client);
                let _ = record_event(
                    &app,
                    "allowed",
                    "forwarded",
                    "DNS query forwarded",
                    Some(&domain),
                );
            }
            Err(_) => {
                let _ = record_event(
                    &app,
                    "dns_error",
                    "failed",
                    "Upstream DNS query failed",
                    Some(&domain),
                );
            }
        }
    }
}

fn is_blocked(app: &AppHandle, domain: &str) -> bool {
    let Ok((connection, _)) = open_database(app) else {
        return false;
    };
    let Ok(mut statement) =
        connection.prepare("SELECT domain FROM blocked_domains WHERE enabled = 1")
    else {
        return false;
    };
    let Ok(rows) = statement.query_map([], |row| row.get::<_, String>(0)) else {
        return false;
    };
    let matches = rows
        .flatten()
        .any(|blocked| domain_matches(domain, &blocked));
    matches
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
    socket
        .send_to(packet, UPSTREAM_ADDR)
        .map_err(|error| format!("Unable to send upstream DNS query: {error}"))?;
    let mut response = [0_u8; 4096];
    let (size, _source): (usize, SocketAddr) = socket
        .recv_from(&mut response)
        .map_err(|error| format!("Unable to receive upstream DNS response: {error}"))?;
    Ok(response[..size].to_vec())
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
