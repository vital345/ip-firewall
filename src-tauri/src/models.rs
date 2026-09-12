use serde::Serialize;

pub const BLOCK_START: &str = "# IP-FIREWALL:START";
pub const BLOCK_END: &str = "# IP-FIREWALL:END";

#[derive(Debug, Serialize)]
pub struct BlockerState {
    pub enabled: bool,
    pub domain_count: usize,
    pub observed_blocked_requests: u64,
    pub hosts_path: String,
    pub operating_system: String,
    pub sinkhole_backend: String,
    pub host_writeable: bool,
}

#[derive(Debug, Serialize)]
pub struct ActivityEvent {
    pub id: i64,
    pub created_at: String,
    pub kind: String,
    pub domain: Option<String>,
    pub action: String,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct BlocklistEntry {
    pub domain: String,
    pub category: String,
    pub source: String,
    pub enabled: bool,
    pub redirect: String,
    pub notes: String,
}

#[derive(Debug, Serialize)]
pub struct DashboardData {
    pub state: BlockerState,
    pub events: Vec<ActivityEvent>,
    pub blocklist: Vec<BlocklistEntry>,
    pub database_path: String,
}
