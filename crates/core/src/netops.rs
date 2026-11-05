//! Extra network tools: wake-on-LAN, a port knock, ping, traceroute, a link-time
//! check, and a connection card you can paste somewhere else.
//!
//! Nothing here stores or prints a password. The card is built only from the saved
//! session (host, user, port, jump hosts, key path, note).

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::error::{AppError, ErrorCode};
use crate::sessions::{SavedSession, SessionsFile, SshAuth, SshExtras};
use crate::ssh::chain::resolve_chain;

fn invalid(message: &str) -> AppError {
    AppError::new(ErrorCode::InvalidInput, message)
}

fn failed(message: &str) -> AppError {
    AppError::new(ErrorCode::ConnectionFailed, message)
}

/// A host name safe to pass as one argument to ping or traceroute.
/// It cannot start with a dash, so it is never read as a program option.
pub fn check_probe_host(host: &str) -> Result<(), AppError> {
    if host.is_empty()
        || host.len() > 253
        || host.starts_with('-')
        || host
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || ";&|$`<>\\\"'".contains(c))
    {
        return Err(invalid("That host name isn't valid."));
    }
    Ok(())
}

/// Six address bytes, from `aa:bb:cc:dd:ee:ff`, `aa-bb-...` or `aabbccddeeff`.
pub fn parse_mac(text: &str) -> Result<[u8; 6], AppError> {
    let hex: String = text
        .chars()
        .filter(|c| *c != ':' && *c != '-' && !c.is_whitespace())
        .collect();
    if hex.len() != 12 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid(
            "A wake address looks like aa:bb:cc:dd:ee:ff (the computer's MAC address).",
        ));
    }
    let mut out = [0u8; 6];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0);
    }
    Ok(out)
}

/// The WoL magic packet: six 0xFF bytes, then the MAC address sixteen times.
pub fn magic_packet(mac: [u8; 6]) -> Vec<u8> {
    let mut packet = vec![0xff; 6];
    for _ in 0..16 {
        packet.extend_from_slice(&mac);
    }
    packet
}

/// Broadcasts a wake packet, and also sends it straight at `host` when that is set.
pub fn send_wake(mac: &str, host: &str) -> Result<(), AppError> {
    if !host.is_empty() {
        check_probe_host(host)?;
    }
    let packet = magic_packet(parse_mac(mac)?);
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|_| failed("Couldn't open a socket to send the wake packet."))?;
    socket
        .set_broadcast(true)
        .map_err(|_| failed("Couldn't send a broadcast on this network."))?;
    let _ = socket.set_write_timeout(Some(Duration::from_secs(2)));
    socket
        .send_to(&packet, SocketAddr::from((Ipv4Addr::BROADCAST, 9)))
        .map_err(|_| failed("Couldn't send the wake packet. The network may block broadcasts."))?;
    if !host.is_empty() {
        let _ = socket.send_to(&packet, (host, 9));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Knock {
    pub port: u16,
    pub udp: bool,
}

/// `7000, 8000/udp, 443/tcp`. Empty means there is nothing to knock.
pub fn parse_knock(text: &str) -> Result<Vec<Knock>, AppError> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(Vec::new());
    }
    let mut steps = Vec::new();
    for raw in text.split(|c: char| c == ',' || c.is_whitespace()) {
        if raw.is_empty() {
            continue;
        }
        let (port_text, udp) = match raw.split_once('/') {
            Some((port, kind)) => {
                let kind = kind.trim().to_ascii_lowercase();
                if kind != "tcp" && kind != "udp" {
                    return Err(invalid(
                        "A knock is a port, or a port followed by /tcp or /udp.",
                    ));
                }
                (port.trim(), kind == "udp")
            }
            None => (raw.trim(), false),
        };
        let port: u16 = port_text
            .parse()
            .map_err(|_| invalid("Each knock needs a port between 1 and 65535."))?;
        if port == 0 {
            return Err(invalid("Each knock needs a port between 1 and 65535."));
        }
        steps.push(Knock { port, udp });
        if steps.len() > 8 {
            return Err(invalid("A knock sequence can have at most 8 ports."));
        }
    }
    if steps.is_empty() {
        return Err(invalid(
            "A knock is a port, or a port followed by /tcp or /udp.",
        ));
    }
    Ok(steps)
}

/// Taps each port in order, then waits a moment. Used just before a direct SSH connection.
pub async fn knock_host(host: &str, spec: &str) -> Result<(), AppError> {
    let steps = parse_knock(spec)?;
    for (i, step) in steps.iter().enumerate() {
        if step.udp {
            let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
                .map_err(|_| failed("Couldn't open a socket for the port knock."))?;
            let _ = socket.set_write_timeout(Some(Duration::from_millis(300)));
            socket
                .send_to(&[0], (host, step.port))
                .map_err(|_| failed("The port knock didn't go out."))?;
        } else {
            let _ = timeout(
                Duration::from_millis(300),
                TcpStream::connect((host, step.port)),
            )
            .await;
        }
        if i + 1 != steps.len() {
            tokio::time::sleep(Duration::from_millis(120)).await;
        }
    }
    Ok(())
}

pub fn check_extras(extras: &SshExtras) -> Result<(), AppError> {
    if !extras.mac.trim().is_empty() {
        parse_mac(extras.mac.trim())?;
    }
    parse_knock(&extras.knock)?;
    if extras.note.len() > 2000
        || extras
            .note
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err(invalid(
            "The note must be plain text, up to 2000 characters. Don't put passwords in it.",
        ));
    }
    if extras.bookmarks.len() > 40 {
        return Err(invalid("A session can keep at most 40 folder bookmarks."));
    }
    for path in &extras.bookmarks {
        if path.is_empty() || path.len() > 500 || path.chars().any(|c| c.is_control()) {
            return Err(invalid("A folder bookmark must be a plain path."));
        }
    }
    Ok(())
}

fn shell_token(text: &str) -> String {
    if !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._:-".contains(c))
    {
        text.to_string()
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

/// An `ssh` command for this session, including jump hosts. It never contains a password.
pub fn openssh_command(file: &SessionsFile, id: &str) -> Result<String, AppError> {
    let chain = resolve_chain(file, id)?;
    let last = chain
        .last()
        .ok_or_else(|| invalid("There is nothing to connect to."))?;
    let mut parts = vec!["ssh".to_string(), "-p".into(), last.port.to_string()];
    if let Some(SavedSession::Ssh {
        auth: SshAuth::Key,
        key_path,
        ..
    }) = file.sessions.iter().find(|s| s.id() == id)
        && !key_path.is_empty()
    {
        parts.push("-i".into());
        parts.push(shell_token(key_path));
    }
    if chain.len() > 1 {
        let jumps = chain
            .iter()
            .take(chain.len() - 1)
            .map(|hop| {
                format!(
                    "{}@{}:{}",
                    shell_token(&hop.user),
                    shell_token(&hop.host),
                    hop.port
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        parts.push("-J".into());
        parts.push(jumps);
    }
    parts.push(format!(
        "{}@{}",
        shell_token(&last.user),
        shell_token(&last.host)
    ));
    Ok(parts.join(" "))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectionCard {
    /// The ssh command on its own, for a terminal.
    pub command: String,
    /// A short note you can paste into a chat. No passwords.
    pub card: String,
}

pub fn connection_card(file: &SessionsFile, id: &str) -> Result<ConnectionCard, AppError> {
    let command = openssh_command(file, id)?;
    let SavedSession::Ssh {
        name,
        user,
        host,
        port,
        auth,
        extras,
        ..
    } = file.sessions.iter().find(|s| s.id() == id).ok_or_else(|| {
        AppError::new(
            ErrorCode::NotFound,
            "That saved session doesn't exist any more.",
        )
    })?
    else {
        return Err(invalid("That isn't an SSH session."));
    };
    let chain = resolve_chain(file, id)?;
    let login = match auth {
        SshAuth::Password => "password, asked when you connect",
        SshAuth::Key => "a private key file",
        SshAuth::Agent => "the SSH agent",
    };
    let mut lines = vec![
        name.clone(),
        format!("{user}@{host}:{port}"),
        format!("Login: {login}"),
    ];
    if chain.len() > 1 {
        let via = chain
            .iter()
            .take(chain.len() - 1)
            .map(|hop| format!("{}@{}", hop.user, hop.host))
            .collect::<Vec<_>>()
            .join(" → ");
        lines.push(format!("Through: {via}"));
    }
    if !extras.mac.trim().is_empty() {
        lines.push(format!("Wake-on-LAN: {}", extras.mac.trim()));
    }
    if !extras.knock.trim().is_empty() {
        lines.push(format!("Port knock: {}", extras.knock.trim()));
    }
    if !extras.note.trim().is_empty() {
        lines.push(String::new());
        lines.push(extras.note.trim().to_string());
    }
    lines.push(String::new());
    lines.push(command);
    lines.push(String::new());
    lines.push("No passwords are included.".into());
    Ok(ConnectionCard {
        command: openssh_command(file, id)?,
        card: lines.join("\n"),
    })
}

/// How long a TCP connection to this host takes, in milliseconds.
pub async fn tcp_probe(host: &str, port: u16) -> Result<u32, AppError> {
    check_probe_host(host)?;
    if port == 0 {
        return Err(invalid("The port must be between 1 and 65535."));
    }
    let started = Instant::now();
    match timeout(Duration::from_secs(2), TcpStream::connect((host, port))).await {
        Ok(Ok(_stream)) => Ok(started.elapsed().as_millis().min(60_000) as u32),
        Ok(Err(_)) => Err(failed("Couldn't reach that computer.")),
        Err(_) => Err(failed("That computer didn't answer in time.")),
    }
}

fn capture(mut cmd: Command) -> Result<String, AppError> {
    let output = cmd.output().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            failed("That program isn't installed on this computer.")
        } else {
            failed("Couldn't start that program.")
        }
    })?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    let err = String::from_utf8_lossy(&output.stderr);
    if !err.trim().is_empty() {
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(err.trim());
    }
    if text.len() > 24_000 {
        text.truncate(24_000);
        text.push_str("\n…");
    }
    let text = text.trim().to_string();
    if text.is_empty() {
        return Err(failed("The program finished without printing anything."));
    }
    Ok(text)
}

fn ping_command(host: &str) -> Command {
    let mut cmd = Command::new("ping");
    cmd.stdin(Stdio::null());
    if cfg!(windows) {
        cmd.args(["-n", "4", "-w", "1000", host]);
    } else {
        cmd.args(["-c", "4", "-W", "2", host]);
    }
    cmd
}

fn trace_command(host: &str) -> Command {
    let mut cmd = if cfg!(windows) {
        let mut cmd = Command::new("tracert");
        cmd.args(["-d", "-h", "12", "-w", "800", host]);
        cmd
    } else {
        let mut cmd = Command::new("traceroute");
        cmd.args(["-n", "-m", "12", "-w", "2", host]);
        cmd
    };
    cmd.stdin(Stdio::null());
    cmd
}

pub async fn run_ping(host: &str) -> Result<String, AppError> {
    check_probe_host(host)?;
    let host = host.to_string();
    tokio::task::spawn_blocking(move || capture(ping_command(&host)))
        .await
        .map_err(|_| failed("Ping was interrupted."))?
}

pub async fn run_trace(host: &str) -> Result<String, AppError> {
    check_probe_host(host)?;
    let host = host.to_string();
    tokio::task::spawn_blocking(move || capture(trace_command(&host)))
        .await
        .map_err(|_| failed("Traceroute was interrupted."))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions::SshAuth;

    fn ssh(id: &str, jump: &str) -> SavedSession {
        SavedSession::Ssh {
            id: id.into(),
            name: "Build".into(),
            folder: String::new(),
            host: format!("{id}.example"),
            port: 22,
            user: "alex".into(),
            auth: SshAuth::Agent,
            key_path: String::new(),
            jump: jump.into(),
            x11: false,
            color: String::new(),
            startup: String::new(),
            extras: SshExtras::default(),
        }
    }

    #[test]
    fn the_magic_packet_repeats_the_address() {
        let mac = parse_mac("AA:bb-cc dd:ee:01").unwrap();
        let packet = magic_packet(mac);
        assert_eq!(packet.len(), 6 + 16 * 6);
        assert!(packet[..6].iter().all(|b| *b == 0xff));
        assert_eq!(&packet[6..12], &mac);
        assert_eq!(&packet[packet.len() - 6..], &mac);
    }

    #[test]
    fn a_bad_mac_or_knock_is_refused() {
        assert!(parse_mac("zz:zz:zz:zz:zz:zz").is_err());
        assert!(parse_mac("aa:bb").is_err());
        assert!(parse_knock("0").is_err());
        assert!(parse_knock("22/icmp").is_err());
        assert!(parse_knock("1,2,3,4,5,6,7,8,9").is_err());
        let steps = parse_knock(" 7000, 8000/udp  443/tcp ").unwrap();
        assert_eq!(
            steps,
            vec![
                Knock {
                    port: 7000,
                    udp: false
                },
                Knock {
                    port: 8000,
                    udp: true
                },
                Knock {
                    port: 443,
                    udp: false
                },
            ]
        );
        assert!(parse_knock("").unwrap().is_empty());
    }

    #[test]
    fn the_ssh_command_includes_the_jump_and_never_a_password() {
        let mut target = ssh("web", "jump");
        if let SavedSession::Ssh {
            port,
            auth,
            key_path,
            extras,
            ..
        } = &mut target
        {
            *port = 2222;
            *auth = SshAuth::Key;
            *key_path = "C:\\keys\\id".into();
            extras.note = "do not put a password here".into();
        }
        let file = SessionsFile {
            version: 1,
            folders: vec![],
            sessions: vec![ssh("jump", ""), target],
        };
        let card = connection_card(&file, "web").unwrap();
        assert_eq!(
            card.command,
            "ssh -p 2222 -i 'C:\\keys\\id' -J alex@jump.example:22 alex@web.example"
        );
        assert!(card.card.contains("No passwords are included."));
        assert!(card.card.contains("do not put a password here"));
        assert!(!card.card.to_lowercase().contains("secret"));
    }

    #[test]
    fn a_probe_host_cannot_be_a_program_option() {
        assert!(check_probe_host("-n").is_err());
        assert!(check_probe_host("ok.example").is_ok());
        assert!(check_probe_host("a b").is_err());
    }

    #[tokio::test]
    async fn a_knock_reaches_a_local_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let spec = port.to_string();
        let knocking = tokio::spawn(async move { knock_host("127.0.0.1", &spec).await.unwrap() });
        let _ = timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        knocking.await.unwrap();
    }
}
