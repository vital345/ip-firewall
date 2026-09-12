import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import {
  type ChangeEvent,
  type FormEvent,
  useEffect,
  useRef,
  useState,
} from "react";
import "./App.css";

type BlockerState = {
  enabled: boolean;
  domain_count: number;
  observed_blocked_requests: number;
  hosts_path: string;
  operating_system: string;
  sinkhole_backend: string;
  host_writeable: boolean;
  protection_supported: boolean;
  packet_filter_backend: string;
  packet_filter_enabled: boolean;
  packet_filter_note: string;
};

type ActivityEvent = {
  id: number;
  created_at: string;
  kind: string;
  domain: string | null;
  action: string;
  detail: string;
};

type BlocklistEntry = {
  domain: string;
  category: string;
  source: string;
  enabled: boolean;
  redirect: string;
  notes: string;
};

type DashboardData = {
  state: BlockerState;
  events: ActivityEvent[];
  blocklist: BlocklistEntry[];
  database_path: string;
};

type Page = "overview" | "activity" | "blocklist";

const initialData: DashboardData = {
  state: {
    enabled: false,
    domain_count: 0,
    observed_blocked_requests: 0,
    hosts_path: "",
    operating_system: "Cross-platform",
    sinkhole_backend: "Hosts file sinkhole",
    host_writeable: true,
    protection_supported: true,
    packet_filter_backend: "unavailable",
    packet_filter_enabled: false,
    packet_filter_note: "Waiting for native enforcement status",
  },
  events: [],
  blocklist: [],
  database_path: "",
};

function formatTime(timestamp: string) {
  const date = new Date(Number(timestamp) * 1000);
  return Number.isNaN(date.getTime())
    ? timestamp
    : date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function App() {
  const [page, setPage] = useState<Page>("overview");
  const [data, setData] = useState(initialData);
  const [newDomain, setNewDomain] = useState("");
  const [newCategory, setNewCategory] = useState("advertising");
  const [newSource, setNewSource] = useState("manual");
  const [newNotes, setNewNotes] = useState("");
  const [blocklistQuery, setBlocklistQuery] = useState("");
  const [pageSize, setPageSize] = useState(10);
  const [currentPage, setCurrentPage] = useState(1);
  const [isLoading, setIsLoading] = useState(true);
  const [isUpdating, setIsUpdating] = useState(false);
  const [error, setError] = useState("");
  const importInputRef = useRef<HTMLInputElement>(null);

  async function loadDashboard() {
    try {
      setData(await invoke<DashboardData>("get_dashboard"));
      setError("");
    } catch (message) {
      setError(String(message));
    } finally {
      setIsLoading(false);
    }
  }

  useEffect(() => {
    void loadDashboard();
    const timer = window.setInterval(() => void loadDashboard(), 2000);
    return () => window.clearInterval(timer);
  }, []);

  async function toggleBlocker() {
    if (!data.state.protection_supported) {
      setError(
        "This operating system requires a platform-specific DNS or VPN backend that IP Firewall does not provide yet.",
      );
      return;
    }
    setIsUpdating(true);
    setError("");
    try {
      setData(
        await invoke<DashboardData>("set_blocker_enabled", {
          enabled: !data.state.enabled,
        }),
      );
    } catch (message) {
      setError(String(message));
    } finally {
      setIsUpdating(false);
    }
  }

  async function clearActivity() {
    try {
      setData(await invoke<DashboardData>("clear_activity"));
    } catch (message) {
      setError(String(message));
    }
  }

  async function addDomain(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const trimmed = newDomain.trim();
    if (!trimmed) {
      return;
    }

    try {
      setData(
        await invoke<DashboardData>("add_domain", {
          domain: trimmed,
          category: newCategory,
          source: newSource.trim() || "manual",
          notes: newNotes.trim(),
        }),
      );
      setNewDomain("");
      setNewNotes("");
      setError("");
    } catch (message) {
      setError(String(message));
    }
  }

  async function removeDomain(domain: string) {
    try {
      setData(await invoke<DashboardData>("remove_domain", { domain }));
      setError("");
    } catch (message) {
      setError(String(message));
    }
  }

  async function exportBlocklist() {
    const path = await save({
      defaultPath: "ip-firewall-blocklist.json",
      filters: [{ name: "JSON file", extensions: ["json"] }],
    });
    if (path) {
      await invoke("save_export", {
        path,
        contents: JSON.stringify(data.blocklist, null, 2),
      });
    }
  }

  async function exportBlocklistCsv() {
    const csv = [
      "domain,category,source,enabled,redirect,notes",
      ...data.blocklist.map((entry) =>
        [
          entry.domain,
          entry.category,
          entry.source,
          entry.enabled,
          entry.redirect,
          entry.notes,
        ]
          .map((value) => `"${String(value).split('"').join('""')}"`)
          .join(","),
      ),
    ].join("\r\n");
    const path = await save({
      defaultPath: "ip-firewall-blocklist.csv",
      filters: [{ name: "CSV file", extensions: ["csv"] }],
    });
    if (path) {
      await invoke("save_export", { path, contents: `${csv}\r\n` });
    }
  }

  async function saveTextExport(
    defaultPath: string,
    extension: string,
    contents: string,
  ) {
    const path = await save({
      defaultPath,
      filters: [
        { name: `${extension.toUpperCase()} file`, extensions: [extension] },
      ],
    });
    if (path) {
      await invoke("save_export", { path, contents });
    }
  }

  async function exportActivityJson() {
    await saveTextExport(
      "ip-firewall-activity.json",
      "json",
      JSON.stringify(data.events, null, 2),
    );
  }

  async function exportActivityCsv() {
    const escapeCsv = (value: string | number | null) =>
      `"${String(value ?? "")
        .split('"')
        .join('""')}"`;
    const rows = [
      ["id", "created_at", "kind", "domain", "action", "detail"],
      ...data.events.map((event) => [
        event.id,
        event.created_at,
        event.kind,
        event.domain,
        event.action,
        event.detail,
      ]),
    ];
    const csv = rows.map((row) => row.map(escapeCsv).join(",")).join("\r\n");
    await saveTextExport("ip-firewall-activity.csv", "csv", `${csv}\r\n`);
  }

  function parseCsvDomains(contents: string): string[] {
    return contents.split(/\r?\n/).flatMap((line, index) => {
      const trimmed = line.trim();
      if (!trimmed || (index === 0 && trimmed.toLowerCase() === "domain")) {
        return [];
      }

      const firstValue = trimmed.split(",", 1)[0].trim();
      return [firstValue.replace(/^"|"$/g, "").split('""').join('"')];
    });
  }

  function parseImportedDomains(contents: string): string[] {
    try {
      const parsed: unknown = JSON.parse(contents);
      if (Array.isArray(parsed)) {
        return parsed.flatMap((value) => {
          if (typeof value === "string") {
            return [value];
          }
          if (
            value !== null &&
            typeof value === "object" &&
            "domain" in value &&
            typeof value.domain === "string"
          ) {
            return [value.domain];
          }
          return [];
        });
      }
      if (
        parsed !== null &&
        typeof parsed === "object" &&
        "domains" in parsed &&
        Array.isArray(parsed.domains)
      ) {
        return parsed.domains.filter(
          (value): value is string => typeof value === "string",
        );
      }
    } catch {
      // Plain text and uBlock filter lists are handled below.
    }

    const ublockRule = /^\|\|([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)\^/i;
    const lines = contents.split(/\r?\n/);
    if (
      lines.some((line) => line.includes(",")) ||
      lines[0]?.trim().toLowerCase() === "domain"
    ) {
      return parseCsvDomains(contents);
    }

    return lines.flatMap((line) => {
      const trimmed = line.trim();
      const rule = trimmed.match(ublockRule);
      if (rule) {
        return [rule[1]];
      }
      if (!trimmed || trimmed.startsWith("!") || trimmed.startsWith("#")) {
        return [];
      }
      return trimmed.split(",", 1);
    });
  }

  async function importBlocklist(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) {
      return;
    }

    try {
      const domains = parseImportedDomains(await file.text());
      setData(await invoke<DashboardData>("import_domains", { domains }));
      setError("");
    } catch (message) {
      setError(String(message));
    }
  }

  const { state, events } = data;
  const filteredDomains = data.blocklist.filter((entry) =>
    [entry.domain, entry.category, entry.source, entry.notes]
      .join(" ")
      .toLowerCase()
      .includes(blocklistQuery.trim().toLowerCase()),
  );
  const totalPages = Math.max(1, Math.ceil(filteredDomains.length / pageSize));
  const safePage = Math.min(currentPage, totalPages);
  const visibleDomains = filteredDomains.slice(
    (safePage - 1) * pageSize,
    safePage * pageSize,
  );

  useEffect(() => {
    if (currentPage > totalPages) {
      setCurrentPage(totalPages);
    }
  }, [currentPage, totalPages]);

  useEffect(() => {
    setCurrentPage(1);
  }, [pageSize, blocklistQuery]);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">+</span>
          <span>IP FIREWALL</span>
        </div>
        <nav>
          <button
            className={`nav-item ${page === "overview" ? "active" : ""}`}
            onClick={() => setPage("overview")}
          >
            <span>◉</span> Overview
          </button>
          <button
            className={`nav-item ${page === "activity" ? "active" : ""}`}
            onClick={() => setPage("activity")}
          >
            <span>⌁</span> Activity <em>{events.length || ""}</em>
          </button>
          <button
            className={`nav-item ${page === "blocklist" ? "active" : ""}`}
            onClick={() => setPage("blocklist")}
          >
            <span>⊘</span> Blocklist
          </button>
        </nav>
        <div className="sidebar-footer">
          <div className="system-label">SYSTEM STATUS</div>
          <div className="system-state">
            <span className={`status-dot ${state.enabled ? "on" : ""}`} />{" "}
            {state.enabled ? "Protected" : "Standby"}
          </div>
          <div className="version">
            v0.1.0 / {state.operating_system || "Cross-platform"} /{" "}
            {state.sinkhole_backend}
          </div>
        </div>
      </aside>

      <main className="content">
        <header className="topbar">
          <div>
            <p className="eyebrow">DEVICE PROTECTION / {page.toUpperCase()}</p>
            <h1>
              {page === "overview"
                ? "Quiet the noise."
                : page === "activity"
                  ? "Know what happened."
                  : "Your blocklist."}
            </h1>
          </div>
          <div className="header-meta">
            <span className={`status-pill ${state.enabled ? "live" : ""}`}>
              <i /> {state.enabled ? "LIVE" : "OFFLINE"}
            </span>
            <span className="time">AUTO REFRESH 2S</span>
          </div>
        </header>

        {page === "overview" && (
          <>
            <section className="hero-panel">
              <div className="hero-copy">
                <div className="shield-icon">✦</div>
                <div>
                  <p className="eyebrow">ADVERTISING TRAFFIC FILTER</p>
                  <h2>
                    {state.enabled
                      ? "Your device is quiet."
                      : "Your device is exposed."}
                  </h2>
                  <p className="hero-description">
                    {state.enabled
                      ? "Known advertising endpoints are being sinkholed before they reach your apps."
                      : "Enable protection to stop known advertising endpoints across this system."}
                  </p>
                </div>
              </div>
              <button
                className={`power-button ${state.enabled ? "enabled" : ""}`}
                onClick={toggleBlocker}
                disabled={
                  isLoading || isUpdating || !state.protection_supported
                }
              >
                <span className="power-symbol">⏻</span>
                <span>
                  {isUpdating
                    ? "UPDATING"
                    : !state.protection_supported
                      ? "UNSUPPORTED PLATFORM"
                      : state.enabled
                        ? "PROTECTED"
                        : "PROTECT DEVICE"}
                </span>
              </button>
            </section>
            <section className="metrics">
              <article className="metric-card">
                <span className="metric-label">OBSERVED BLOCKED REQUESTS</span>
                <strong>{state.observed_blocked_requests}</strong>
                <span className="metric-note">
                  Requires a DNS proxy backend
                </span>
              </article>
              <article className="metric-card accent">
                <span className="metric-label">DOMAINS COVERED</span>
                <strong>{state.domain_count}</strong>
                <span className="metric-note">
                  Curated advertising endpoints
                </span>
              </article>
              <article className="metric-card">
                <span className="metric-label">FILTER MODE</span>
                <strong>
                  {state.packet_filter_enabled ? "PACKET" : "DNS"}
                </strong>
                <span className="metric-note">
                  {state.packet_filter_backend}
                </span>
              </article>
            </section>
            <section className="lower-grid">
              <article className="panel">
                <div className="panel-heading">
                  <div>
                    <p className="eyebrow">PERSISTENCE</p>
                    <h3>Local activity database</h3>
                  </div>
                  <span className="mini-tag">SQLITE</span>
                </div>
                <div className="database-row">
                  <span className="db-light" />{" "}
                  <span>
                    {data.database_path || "Waiting for desktop bridge"}
                  </span>
                </div>
                <p className="panel-copy">
                  State changes and future filter events are stored locally. The
                  dashboard polls the database every two seconds.
                </p>
              </article>
              <article className="panel">
                <div className="panel-heading">
                  <div>
                    <p className="eyebrow">TELEMETRY STATUS</p>
                    <h3>{state.packet_filter_backend}</h3>
                  </div>
                  <span className="mini-tag">HONEST</span>
                </div>
                <div className="telemetry-note">
                  <span className="empty-icon">i</span>
                  <p>
                    {state.packet_filter_note} DNS events remain available as an
                    additional visibility layer when the local proxy is active.
                  </p>
                </div>
              </article>
            </section>
          </>
        )}

        {page === "activity" && (
          <section className="page-panel">
            <div className="page-heading">
              <div>
                <p className="eyebrow">SQLITE EVENT LOG</p>
                <h2>Live DNS events</h2>
              </div>
              <div className="activity-actions">
                <button
                  className="outline-button"
                  onClick={exportActivityJson}
                  disabled={!events.length}
                >
                  EXPORT JSON
                </button>
                <button
                  className="outline-button"
                  onClick={exportActivityCsv}
                  disabled={!events.length}
                >
                  EXPORT CSV
                </button>
                <button
                  className="outline-button"
                  onClick={clearActivity}
                  disabled={!events.length}
                >
                  CLEAR LOG
                </button>
              </div>
            </div>
            {events.length ? (
              <div className="event-list">
                {events.map((event) => (
                  <div className="event-row" key={event.id}>
                    <span className={`event-icon ${event.kind}`}>
                      {event.kind === "blocked" ? "⊘" : "✓"}
                    </span>
                    <div>
                      <strong>
                        {event.kind === "blocked" && event.domain
                          ? event.domain
                          : event.detail}
                      </strong>
                      <small>
                        {event.kind === "blocked"
                          ? `${event.detail} / ${event.action}`
                          : `${event.action}${event.domain ? ` / ${event.domain}` : ""}`}
                      </small>
                    </div>
                    <time>{formatTime(event.created_at)}</time>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-state large">
                <span className="empty-icon">⌁</span>
                <p>No live DNS events</p>
                <small>
                  Hosts-file mode cannot observe blocked or unfiltered DNS
                  queries. Use a local DNS proxy for real-time telemetry.
                </small>
              </div>
            )}
          </section>
        )}

        {page === "blocklist" && (
          <section className="page-panel">
            <div className="page-heading">
              <div>
                <p className="eyebrow">MANAGED ENDPOINTS</p>
                <h2>{filteredDomains.length} managed endpoints</h2>
              </div>
              <div className="blocklist-actions">
                <button className="outline-button" onClick={exportBlocklist}>
                  EXPORT JSON
                </button>
                <button className="outline-button" onClick={exportBlocklistCsv}>
                  EXPORT CSV
                </button>
                <button
                  className="outline-button"
                  onClick={() => importInputRef.current?.click()}
                >
                  IMPORT FILE
                </button>
                <input
                  ref={importInputRef}
                  className="visually-hidden"
                  type="file"
                  accept=".json,.txt,.csv"
                  onChange={importBlocklist}
                />
                <span className={`mini-tag ${state.enabled ? "tag-live" : ""}`}>
                  {state.enabled ? "ACTIVE" : "READY"}
                </span>
              </div>
            </div>

            <div className="admin-card">
              <form onSubmit={addDomain} className="admin-form">
                <label htmlFor="domain-input">Admin DNS control</label>
                <div className="admin-input-row">
                  <input
                    id="domain-input"
                    value={newDomain}
                    onChange={(event) => setNewDomain(event.target.value)}
                    placeholder="Add a domain like example.com"
                  />
                  <select
                    aria-label="Domain category"
                    value={newCategory}
                    onChange={(event) => setNewCategory(event.target.value)}
                  >
                    <option value="advertising">Advertising</option>
                    <option value="tracking">Tracking</option>
                    <option value="analytics">Analytics</option>
                    <option value="infrastructure">
                      Service infrastructure
                    </option>
                  </select>
                  <input
                    aria-label="Domain source"
                    value={newSource}
                    onChange={(event) => setNewSource(event.target.value)}
                    placeholder="Source"
                  />
                  <input
                    aria-label="Domain notes"
                    value={newNotes}
                    onChange={(event) => setNewNotes(event.target.value)}
                    placeholder="Notes (optional)"
                  />
                  <button type="submit" className="primary-button">
                    ADD DOMAIN
                  </button>
                </div>
              </form>
            </div>

            <div className="table-shell">
              <div className="table-toolbar">
                <label className="search-field" htmlFor="blocklist-search">
                  Search
                  <input
                    id="blocklist-search"
                    value={blocklistQuery}
                    onChange={(event) => setBlocklistQuery(event.target.value)}
                    placeholder="Search domains"
                  />
                </label>
                <div className="page-size-picker">
                  <label htmlFor="page-size">Rows per page</label>
                  <select
                    id="page-size"
                    value={pageSize}
                    onChange={(event) =>
                      setPageSize(Number(event.target.value))
                    }
                  >
                    {[5, 10, 15, 25].map((size) => (
                      <option key={size} value={size}>
                        {size}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <table className="domain-table">
                <thead>
                  <tr>
                    <th>Status</th>
                    <th>Domain</th>
                    <th>Category</th>
                    <th>Source</th>
                    <th>Redirect</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleDomains.map((entry) => (
                    <tr key={entry.domain}>
                      <td>
                        <span className="domain-status" />
                      </td>
                      <td className="domain-name">{entry.domain}</td>
                      <td>{entry.category}</td>
                      <td>{entry.source}</td>
                      <td>{entry.redirect}</td>
                      <td>
                        <button
                          type="button"
                          className="remove-domain"
                          onClick={() => removeDomain(entry.domain)}
                        >
                          REMOVE
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              {!visibleDomains.length && (
                <div className="empty-table">No matching domains</div>
              )}

              <div className="table-pagination">
                <button
                  type="button"
                  className="pagination-button"
                  disabled={safePage <= 1}
                  onClick={() =>
                    setCurrentPage((value) => Math.max(1, value - 1))
                  }
                >
                  Previous
                </button>
                <span>
                  Page {safePage} of {totalPages}
                </span>
                <button
                  type="button"
                  className="pagination-button"
                  disabled={safePage >= totalPages}
                  onClick={() =>
                    setCurrentPage((value) => Math.min(totalPages, value + 1))
                  }
                >
                  Next
                </button>
              </div>
            </div>
          </section>
        )}

        {error && (
          <div className="error-banner">
            <span>!</span>
            {error}
          </div>
        )}
        <footer className="footer-note">
          <span>Protection is applied at the device level.</span>
          <span>Managed file: {state.hosts_path || "not connected"}</span>
        </footer>
      </main>
    </div>
  );
}

export default App;
