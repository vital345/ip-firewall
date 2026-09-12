mod commands;
mod database;
mod dns_proxy;
mod models;
mod sinkhole;

use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(std::sync::Mutex::new(dns_proxy::DnsProxyHandle::default()))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            if sinkhole::read_hosts()?.contains(models::BLOCK_START) {
                let proxy = app.state::<std::sync::Mutex<dns_proxy::DnsProxyHandle>>();
                if let Ok(mut proxy) = proxy.lock() {
                    let _ = proxy.start(app.handle().clone());
                };
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
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
