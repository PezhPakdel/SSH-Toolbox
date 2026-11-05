//! Wake-on-LAN, ping, traceroute, the link-time check, and the connection card.

use toolbox_core::error::AppError;
use toolbox_core::netops::{self, ConnectionCard};
use toolbox_core::sessions::SessionsFile;

/// A card and an `ssh` command for a saved session. Neither contains a password.
#[tauri::command]
pub fn connection_card(file: SessionsFile, session_id: String) -> Result<ConnectionCard, AppError> {
    file.validate()?;
    netops::connection_card(&file, &session_id)
}

/// Broadcasts a wake packet. `host` may be empty; the packet still goes to the whole network.
#[tauri::command]
pub fn wol_send(mac: String, host: String) -> Result<(), AppError> {
    netops::send_wake(mac.trim(), host.trim())
}

#[tauri::command]
pub async fn net_ping(host: String) -> Result<String, AppError> {
    netops::run_ping(host.trim()).await
}

#[tauri::command]
pub async fn net_trace(host: String) -> Result<String, AppError> {
    netops::run_trace(host.trim()).await
}

/// Milliseconds to open a TCP connection, for the footer.
#[tauri::command]
pub async fn link_probe(host: String, port: u16) -> Result<u32, AppError> {
    netops::tcp_probe(host.trim(), port).await
}
