mod commands;
mod database;
mod models;
mod sinkhole;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
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
