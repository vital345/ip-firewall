mod commands;
mod database;
mod dns_proxy;
mod models;
mod sinkhole;
mod system_dns;

use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(std::sync::Mutex::new(dns_proxy::DnsProxyHandle::default()))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            if sinkhole::read_hosts()?.contains(models::BLOCK_START) {
                let _ = system_dns::configure_local_dns(app.handle());
                let proxy = app.state::<std::sync::Mutex<dns_proxy::DnsProxyHandle>>();
                let mut proxy = proxy
                    .lock()
                    .map_err(|_| "Unable to access the DNS proxy state.".to_string())?;
                if let Err(error) = proxy.start(app.handle().clone()) {
                    let _ = system_dns::restore_dns(app.handle());
                    eprintln!("Unable to restart DNS proxy: {error}");
                }
            } else {
                let _ = system_dns::restore_dns(app.handle());
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_dashboard,
            commands::set_blocker_enabled,
            commands::add_domain,
            commands::import_domains,
            commands::save_export,
            commands::remove_domain,
            commands::clear_activity,
        ])
        .build(tauri::generate_context!())
        .expect("error while running tauri application")
        .run(|app, event| {
            if matches!(event, tauri::RunEvent::Exit) {
                let _ = system_dns::restore_dns(app);
            }
        });
}
