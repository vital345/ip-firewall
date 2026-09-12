# IP Firewall

Device-wide advertisement filtering. IP Firewall maintains a clearly marked block in the system hosts file and maps known advertising domains to `0.0.0.0`, so those domains are stopped before they reach applications, including Edge when it uses the operating system resolver.

## Run

From PowerShell in the project directory, install the frontend dependencies and start the Tauri desktop app:

```bash
npm install
npm run tauri dev
```

On Windows, start PowerShell or VS Code as **Administrator** before running the app. Administrator privileges are required when you enable protection because IP Firewall edits `C:\Windows\System32\drivers\etc\hosts`. The app only edits the block between `# IP-FIREWALL:START` and `# IP-FIREWALL:END`, leaving the rest of the hosts file untouched.

To verify the project without starting the desktop window:

```bash
npm run build
cargo test --manifest-path src-tauri/Cargo.toml
```

This is DNS-level device filtering, not arbitrary packet inspection. When protection is enabled, IP Firewall also starts a local DNS proxy on `127.0.0.1:53`: blocked domains and their subdomains receive an `NXDOMAIN` response, while allowed queries are forwarded to `1.1.1.1`. Configure the active Windows network adapter to use `127.0.0.1` as its DNS server for other applications to use the proxy. Edge Secure DNS must be disabled or configured to use the operating-system resolver; otherwise it can bypass both the proxy and hosts file. Full packet-level dropping on Windows requires a Windows Filtering Platform driver.

On Windows, list the active adapters with:

```powershell
Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object Name, InterfaceAlias
```

After starting IP Firewall, point the active adapter at the local proxy:

```powershell
Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses 127.0.0.1
```

Replace `Wi-Fi` with the adapter alias shown on your machine. Restore automatic DNS when the proxy is stopped with:

```powershell
Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ResetServerAddresses
```

## Data and activity

The app stores its local SQLite database as `ip-firewall.sqlite3` in the Tauri application data directory. Overview, Activity, and Blocklist are live views backed by the database and refresh every two seconds. Protection enable/disable operations are recorded immediately.

The DNS proxy records actual blocked and forwarded DNS queries as activity events. The hosts-file fallback remains unable to observe individual packets or DNS matches after they leave the operating system resolver.

## Import uBlock domains

The repository includes a dependency-free importer for uBlock hostname rules. Start IP Firewall once so its SQLite database exists, close the app, then preview the import:

```bash
python scripts/import_ublock_blocklist.py --dry-run
```

Apply the import with:

```bash
npm run import:ublock
```

The importer needs the app to have been started once so its SQLite database exists. Close IP Firewall before applying the import, then reopen it to see the imported entries. Use `--dry-run` first if you only want to preview how many domains would be added.

The importer preserves every non-comment uBlock rule in the `filter_rules` table, including network, cosmetic, scriptlet, and redirect rules. It separately extracts simple `||hostname^` rules into `blocked_domains` because only those hostname rules can be applied by the current hosts-file sinkhole. Imported entries are tagged with `source=uBlock import`. To target another database, pass `--database path/to/ip-firewall.sqlite3`.

# Tauri + React + Typescript

This template should help get you started developing with Tauri, React and Typescript in Vite.

## Recommended IDE Setup

# IP Firewall

IP Firewall is a cross-platform desktop application for managing a device-level advertising-domain blocklist. It provides an administrator-facing interface for maintaining blocked DNS domains, enabling or disabling protection, importing public filter lists, exporting configuration and activity, and inspecting the state of the local protection system.

The project is intentionally built in two layers:

- A React and TypeScript desktop interface for administration and visibility.
- A Rust and Tauri backend for persistence, operating-system integration, and hosts-file enforcement.

The current enforcement mechanism is a DNS sinkhole implemented through the operating system hosts file. It is useful, portable, and honest about its boundaries. It is not yet a kernel-level firewall and it does not currently observe every DNS query made by browsers or applications.

## What We Are Trying To Build

The long-term goal is a maintainable device-level advertising and tracking protection tool with these capabilities:

1. Maintain a large, editable list of advertising and tracking domains.
2. Apply that list across the device instead of limiting protection to one browser.
3. Block known domains before applications connect to them.
4. Show which DNS domains were blocked and which were allowed in near real time.
5. Keep all configuration and activity data locally in SQLite.
6. Work across Windows, Linux, and macOS through platform-specific backend implementations rather than scattered operating-system branches.
7. Give administrators practical import, export, search, pagination, and clear-log controls.
8. Preserve user-managed hosts-file content and make changes reversible.

The first version focuses on the administration and persistence foundations. The next major architectural step is a local DNS proxy, which is required for genuine per-query telemetry.

## Current Protection Model

When protection is enabled, IP Firewall writes a clearly marked section to the system hosts file:

```text
# IP-FIREWALL:START
0.0.0.0 example-advertiser.com
0.0.0.0 www.example-advertiser.com
# IP-FIREWALL:END
```

The application only owns the region between the two marker comments. Existing hosts-file entries outside that region are retained. When protection is disabled, the managed region is removed and the rest of the file remains in place.

This approach works by making the operating-system resolver return a sinkhole address for configured domains. It can affect Edge and other applications when they use the operating-system resolver. Edge Secure DNS, browser-specific DNS-over-HTTPS, VPN clients, and applications with their own resolver can bypass the hosts file. For Edge to use this blocklist, Secure DNS must be disabled or configured to use the operating-system resolver.

The backend also performs a best-effort DNS cache flush after hosts-file changes so newly added or removed rules become effective more quickly.

## What The Current Version Can And Cannot Claim

### It can

- Persist blocklist domains in SQLite.
- Seed a new database from `src-tauri/seed_blocklist.sql`.
- Add and remove domains through the UI.
- Import domains from JSON, CSV, plain text, and uBlock-style filter files.
- Import the uBlock filter list from the command line.
- Search and paginate the blocklist.
- Export the blocklist as JSON or CSV.
- Export the activity log as JSON or CSV.
- Enable and disable the managed hosts-file sinkhole.
- Record administrative changes such as enabling protection, adding domains, importing domains, and removing domains.
- Preserve user-owned hosts-file lines outside the managed section.

### It cannot yet

- Observe every DNS query made by Edge or another application.
- Distinguish every real blocked request from every allowed request.
- Provide genuine per-request real-time DNS activity.
- Inspect arbitrary packets or connections.
- Reliably override encrypted DNS used directly by a browser or VPN.
- Provide kernel-level packet filtering without a platform-specific privileged component.

The UI must not fabricate blocked-request data. A configured domain is not the same thing as a domain that was actually requested. The current Activity page therefore records configuration events and deliberately does not claim to be a live DNS packet monitor.

## Application Architecture

### Frontend

The frontend is a React and TypeScript application built with Vite. It contains three main views:

- **Overview**: protection status, domain count, backend information, database location, and operational messaging.
- **Activity**: persisted administrative events with clear-log and JSON/CSV export controls.
- **Blocklist**: searchable and paginated domain table with add, remove, import, and export actions.

The frontend polls `get_dashboard` every two seconds. This makes configuration changes visible quickly, but polling does not create real-time DNS telemetry by itself. The future DNS-proxy implementation should supplement or replace polling with a live event channel while retaining polling as a recovery mechanism.

### Tauri and Rust backend

The backend is split by responsibility:

- `src-tauri/src/lib.rs` bootstraps Tauri, registers plugins, and exposes commands.
- `src-tauri/src/commands.rs` contains the application-facing command handlers.
- `src-tauri/src/database.rs` owns SQLite paths, schema creation, seed loading, event persistence, and queries.
- `src-tauri/src/models.rs` contains serializable state and event models shared with the frontend.
- `src-tauri/src/sinkhole.rs` owns hosts-file paths, platform selection, normalization, managed-block generation, writing, and DNS-cache flushing.
- `src-tauri/seed_blocklist.sql` provides first-run seed data independently from Rust source code.

This separation keeps UI commands thin and prevents database or operating-system details from spreading through the application.

### Database

The application uses SQLite with three primary tables:

```text
blocked_domains
	id
	domain
	added_at
	is_default
	category
	source
	enabled
	redirect
	notes

activity_events
	id
	created_at
	kind
	domain
	action
	detail

filter_rules
	id
	rule
	source
	category
	enabled
	added_at
```

The database is stored in the Tauri application-data directory as `ip-firewall.sqlite3`. On first use, the schema is created and the SQL seed file is inserted only when the blocklist is empty. Existing administrator changes are preserved.

## Domain Management Workflows

### Add a single domain

The Blocklist page normalizes the value, validates that it looks like a hostname, records its category/source/notes metadata, inserts it into SQLite, and refreshes the active hosts sinkhole if protection is enabled. Only enabled entries are written to the managed hosts block.

### Import through the UI

The import control accepts:

- JSON arrays such as `["ads.example.com", "tracker.example"]`.
- JSON objects containing a `domains` array.
- CSV files with a `domain` header or one domain per row.
- Plain text files containing one domain per line.
- uBlock network rules beginning with `||hostname^`.

Invalid values are ignored by the backend normalization step. Existing domains are protected by the database uniqueness constraint and are not duplicated.

### Import the uBlock list from the command line

The dependency-free Python importer downloads the upstream uBlock list, extracts only hostname rules, ignores cosmetic and script-only filters, and inserts new domains into SQLite:

```bash
python scripts/import_ublock_blocklist.py --dry-run
npm run import:ublock
```

The importer supports `--database` when the SQLite file is not at the default Tauri application-data location.

### Export

Blocklist and Activity exports open a native save dialog. The user chooses the destination and filename. The backend writes the selected file path rather than silently placing exports in a browser Downloads directory.

## Activity And Real-Time Telemetry Roadmap

The current Activity log is a configuration log. It is useful for answering questions such as:

- When was protection enabled?
- Which domains were added or removed?
- When was a public blocklist imported?
- When was the activity log cleared?

It is not a request log. To support the requested real-time view of blocked and unfiltered domains, the next backend should be a local DNS proxy:

1. Start a local DNS listener on an available loopback address and port.
2. Configure the operating system resolver to use that listener.
3. Receive DNS queries from Edge and other applications.
4. Normalize the queried hostname.
5. Read the current SQLite blocklist or an in-memory snapshot refreshed from SQLite.
6. If the hostname matches a blocked domain or suffix rule, return a sinkhole response and record a `blocked` event.
7. Otherwise forward the request to a configured upstream resolver and record an `allowed` event.
8. Stream events to the frontend through Tauri events or a command-backed event queue.
9. Keep bounded retention and deduplication so a busy browser does not grow SQLite without limit.
10. Restore the previous DNS configuration when protection is disabled or the application exits.

That architecture would make the following activity record truthful:

```text
time       kind     domain                 action
12:04:01   blocked  ads.example.com        sinkhole response
12:04:02   allowed  cdn.example.com        forwarded upstream
```

The proxy must be implemented carefully for DNS transport details, IPv4/IPv6 resolver configuration, permissions, shutdown recovery, DNS-over-TLS/DNS-over-HTTPS behavior, and platform-specific resolver settings. A Windows Filtering Platform driver remains the correct route for arbitrary packet-level filtering, but it is a larger and more privileged project than a local DNS proxy.

## Running The Project

Install frontend dependencies:

```bash
npm install
```

Run the desktop application in development:

```bash
npm run tauri dev
```

Build the frontend:

```bash
npm run build
```

Run Rust tests:

```bash
cargo test --manifest-path src-tauri/Cargo.toml
```

On Windows, run the application with administrator privileges before enabling hosts-file protection. Without permission to edit the system hosts file, the application can still display and manage its database but cannot apply the device-wide sinkhole.

## Verification And Design Principles

The project follows these practical principles:

- **Truthful telemetry**: never present configured domains as observed requests.
- **Single responsibility**: database, commands, models, sinkhole behavior, and UI remain separate.
- **DRY behavior**: shared normalization, import, save, and managed-block logic lives in one place.
- **Reversible system changes**: only the application-owned hosts-file region is modified.
- **Local-first data**: configuration and activity stay in SQLite on the device.
- **Platform-aware boundaries**: operating-system behavior is isolated behind a backend abstraction.
- **Small, testable transformations**: hostname normalization and managed-block editing are tested independently.

## Project Status

The current release is a maintainable hosts-file and local-DNS sinkhole with SQLite-backed administration, full uBlock rule retention, hostname blocklist search, JSON/CSV import and export, native save dialogs, and DNS/configuration activity logging.

The major unfinished capability is real-time DNS observability. Implementing that capability requires introducing a local DNS proxy or a platform-specific DNS/packet monitoring backend; it cannot be achieved by adding more UI polling to the current hosts-file writer.
