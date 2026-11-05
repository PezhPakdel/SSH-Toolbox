//! Reading SSH sessions out of a MobaXterm export.
//!
//! Accepts a session export (`.mxtsessions`), a full configuration (`.mobaconf`) or
//! `MobaXterm.ini`. Only the bookmark sections are read. Passwords are never copied:
//! a session with a private-key path uses that file, and every other session asks
//! for its password when you connect. Remote desktop, VNC and other session kinds
//! are named and skipped.

use serde::Serialize;

use crate::sessions::{SavedSession, SessionsFile, SshAuth, SshExtras};

const LEFT_OUT_LIMIT: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MobaReport {
    pub sessions_added: usize,
    pub folders_added: usize,
    pub skipped: usize,
    /// Sessions that were not added, in plain language. Capped so a huge file stays readable.
    pub left_out: Vec<String>,
    #[serde(skip)]
    left_out_more: usize,
}

impl MobaReport {
    fn note(&mut self, message: impl Into<String>) {
        if self.left_out.len() < LEFT_OUT_LIMIT {
            self.left_out.push(message.into());
        } else {
            self.left_out_more += 1;
        }
    }

    fn finish(mut self) -> Self {
        if self.left_out_more > 0 {
            self.left_out
                .push(format!("And {} more.", self.left_out_more));
        }
        self
    }
}

/// Adds what the text describes to `file`. Existing sessions with the same host, port
/// and user are left as they are.
pub fn apply_moba(file: &mut SessionsFile, text: &str, default_user: &str) -> MobaReport {
    let mut report = MobaReport {
        sessions_added: 0,
        folders_added: 0,
        skipped: 0,
        left_out: Vec::new(),
        left_out_more: 0,
    };
    let mut saw_bookmarks = false;
    let mut section = String::new();
    let mut folder_path = String::new();

    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_string();
            folder_path.clear();
            if is_bookmarks(&section) {
                saw_bookmarks = true;
            }
            continue;
        }
        if !is_bookmarks(&section)
            || line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
        {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if key.eq_ignore_ascii_case("SubRep") {
            folder_path = value.to_string();
            continue;
        }
        if key.eq_ignore_ascii_case("ImgNum") || !value.starts_with('#') {
            continue;
        }
        add_session(file, &mut report, key, value, &folder_path, default_user);
    }

    if !saw_bookmarks {
        report.note("That file has no MobaXterm session list (a Bookmarks section).");
    }
    report.finish()
}

fn is_bookmarks(section: &str) -> bool {
    section == "Bookmarks" || section.starts_with("Bookmarks_")
}

fn add_session(
    file: &mut SessionsFile,
    report: &mut MobaReport,
    name: &str,
    value: &str,
    folder_path: &str,
    default_user: &str,
) {
    let name = name.trim();
    if name.is_empty() || !plain(name) {
        report.note("One session was skipped because its name isn't plain text.");
        return;
    }
    let parts: Vec<&str> = value.split('#').collect();
    // The value starts with '#', so parts[0] is empty, parts[1] is the icon, parts[2] the fields.
    let fields: Vec<&str> = parts.get(2).unwrap_or(&"").split('%').collect();
    let kind = fields.first().copied().unwrap_or("");
    match kind {
        "0" | "7" => {}
        "4" => {
            report.note(format!(
                "{name} is a remote desktop session, which isn't imported."
            ));
            return;
        }
        "5" => {
            report.note(format!("{name} is a VNC session, which isn't imported."));
            return;
        }
        "11" => {
            report.note(format!(
                "{name} is a browser session, which isn't imported."
            ));
            return;
        }
        _ => {
            report.note(format!("{name} isn't an SSH session, so it was left out."));
            return;
        }
    }

    let host = field(&fields, 1);
    let port = field(&fields, 2).parse::<u16>().unwrap_or(22);
    let mut user = field(&fields, 3);
    if user.is_empty() || user == "<default>" || user == " " {
        user = default_user.to_string();
    }
    if !acceptable_host(&host) || port == 0 || !plain(&user) || user.is_empty() {
        report.note(format!(
            "{name} was left out because its host, port or user isn't usable."
        ));
        return;
    }
    if already(&file.sessions, &host, port, &user) {
        report.skipped += 1;
        return;
    }

    let sftp = kind == "7";
    let (key_path, auth) = if sftp {
        key_auth(&field(&fields, 9))
    } else {
        key_auth(&field(&fields, 14))
    };
    let x11 = !sftp && field(&fields, 5) == "-1";
    let startup = if sftp {
        String::new()
    } else {
        limited_plain(&decode_command(&field(&fields, 7)), 2000)
    };
    let note = limited_plain(&decode_comment(parts.get(5).copied().unwrap_or("")), 2000);
    let color = rgb_color(parts.get(6).copied().unwrap_or("-1"));
    let folder = ensure_folder(file, folder_path, report);
    let jump = gateway(file, report, &fields, &folder, default_user);

    file.sessions.push(SavedSession::Ssh {
        id: uuid::Uuid::new_v4().to_string(),
        name: unique_name(file, name),
        folder,
        host,
        port,
        user,
        auth,
        key_path,
        jump,
        x11,
        color,
        startup,
        extras: SshExtras {
            note,
            ..SshExtras::default()
        },
    });
    report.sessions_added += 1;
}

/// The jump host to go through, or empty. Several gateways are linked in order.
fn gateway(
    file: &mut SessionsFile,
    report: &mut MobaReport,
    fields: &[&str],
    folder: &str,
    default_user: &str,
) -> String {
    let hosts: Vec<String> = field(fields, 8)
        .split("__PIPE__")
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    if hosts.is_empty() {
        return String::new();
    }
    let ports: Vec<String> = field(fields, 9)
        .split("__PIPE__")
        .map(|s| s.to_string())
        .collect();
    let users: Vec<String> = field(fields, 10)
        .split("__PIPE__")
        .map(|s| s.to_string())
        .collect();
    let keys: Vec<String> = field(fields, 15)
        .split("__PIPE__")
        .map(|s| s.to_string())
        .collect();
    let mut previous = String::new();
    for (i, host) in hosts.iter().enumerate() {
        let host = host.clone();
        let port = ports.get(i).and_then(|p| p.parse().ok()).unwrap_or(22);
        let mut user = users.get(i).cloned().unwrap_or_default();
        if user.is_empty() {
            user = default_user.to_string();
        }
        if !acceptable_host(&host) || port == 0 || !plain(&user) {
            report.note(format!("A jump host for {host} was left out."));
            break;
        }
        if let Some(id) = existing_id(&file.sessions, &host, port, &user) {
            previous = id;
            continue;
        }
        let (key_path, auth) = key_auth(keys.get(i).map(String::as_str).unwrap_or(""));
        let id = uuid::Uuid::new_v4().to_string();
        file.sessions.push(SavedSession::Ssh {
            id: id.clone(),
            name: unique_name(file, &format!("{host} jump")),
            folder: folder.to_string(),
            host,
            port,
            user,
            auth,
            key_path,
            jump: previous,
            x11: false,
            color: String::new(),
            startup: String::new(),
            extras: SshExtras::default(),
        });
        report.sessions_added += 1;
        previous = id;
    }
    previous
}

fn field(fields: &[&str], index: usize) -> String {
    fields.get(index).copied().unwrap_or("").trim().to_string()
}

fn key_auth(path: &str) -> (String, SshAuth) {
    // The export writes the C: drive as `_CurrentDrive_:`.
    let path = path
        .replace("_CurrentDrive_:", "C:")
        .replace("_CurrentDrive_", "C:");
    if path.is_empty() || !plain(&path) {
        (String::new(), SshAuth::Password)
    } else {
        (path, SshAuth::Key)
    }
}

fn decode_command(text: &str) -> String {
    text.replace("__PTVIRG__", ";")
        .replace("__DBLQUO__", "\"")
        .replace("__PIPE__", "|")
        .replace("__PERCENT__", "%")
}

fn decode_comment(text: &str) -> String {
    text.replace("__DIEZE__", "#").trim().to_string()
}

/// `#rrggbb` from MobaXterm's decimal colour, or empty when it isn't a real colour.
fn rgb_color(text: &str) -> String {
    let Ok(n) = text.parse::<u32>() else {
        return String::new();
    };
    if n > 0x00ff_ffff {
        return String::new();
    }
    format!(
        "#{:02x}{:02x}{:02x}",
        n & 0xff,
        (n >> 8) & 0xff,
        (n >> 16) & 0xff
    )
}

fn limited_plain(text: &str, max: usize) -> String {
    if text
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return String::new();
    }
    text.chars().take(max).collect()
}

fn plain(text: &str) -> bool {
    text.len() <= 500 && !text.chars().any(|c| c.is_control())
}

fn acceptable_host(host: &str) -> bool {
    !host.is_empty()
        && plain(host)
        && !host.contains(|c: char| c.is_whitespace() || ",[]\"'".contains(c))
}

fn already(sessions: &[SavedSession], host: &str, port: u16, user: &str) -> bool {
    existing_id(sessions, host, port, user).is_some()
}

fn existing_id(sessions: &[SavedSession], host: &str, port: u16, user: &str) -> Option<String> {
    sessions.iter().find_map(|s| match s {
        SavedSession::Ssh {
            id,
            host: h,
            port: p,
            user: u,
            ..
        } if h.eq_ignore_ascii_case(host) && *p == port && u == user => Some(id.clone()),
        _ => None,
    })
}

fn unique_name(file: &SessionsFile, name: &str) -> String {
    let taken = |n: &str| file.sessions.iter().any(|s| s.name() == n);
    if !taken(name) {
        return name.to_string();
    }
    for n in 2..1000 {
        let candidate = format!("{name} ({n})");
        if candidate.len() <= 500 && !taken(&candidate) {
            return candidate;
        }
    }
    name.chars().take(480).collect()
}

/// The folder id for `Work\Lab`, creating any missing level. Empty means the top.
fn ensure_folder(file: &mut SessionsFile, path: &str, report: &mut MobaReport) -> String {
    let mut parent = String::new();
    for part in path
        .split(['\\', '/'])
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        if !plain(part) {
            break;
        }
        if let Some(found) = file
            .folders
            .iter()
            .find(|f| f.parent == parent && f.name == part)
        {
            parent = found.id.clone();
            continue;
        }
        let id = uuid::Uuid::new_v4().to_string();
        file.folders.push(crate::sessions::Folder {
            id: id.clone(),
            name: part.to_string(),
            parent: parent.clone(),
        });
        report.folders_added += 1;
        parent = id;
    }
    parent
}

/// Windows-1252 for the bytes that are not the same as Unicode. MobaXterm writes that charset.
pub fn decode_moba_bytes(bytes: &[u8]) -> String {
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    if let Ok(text) = std::str::from_utf8(bytes) {
        return text.to_string();
    }
    bytes.iter().map(|b| cp1252(*b)).collect()
}

fn cp1252(byte: u8) -> char {
    match byte {
        0x80 => '\u{20AC}',
        0x82 => '\u{201A}',
        0x83 => '\u{0192}',
        0x84 => '\u{201E}',
        0x85 => '\u{2026}',
        0x86 => '\u{2020}',
        0x87 => '\u{2021}',
        0x88 => '\u{02C6}',
        0x89 => '\u{2030}',
        0x8A => '\u{0160}',
        0x8B => '\u{2039}',
        0x8C => '\u{0152}',
        0x8E => '\u{017D}',
        0x91 => '\u{2018}',
        0x92 => '\u{2019}',
        0x93 => '\u{201C}',
        0x94 => '\u{201D}',
        0x95 => '\u{2022}',
        0x96 => '\u{2013}',
        0x97 => '\u{2014}',
        0x98 => '\u{02DC}',
        0x99 => '\u{2122}',
        0x9A => '\u{0161}',
        0x9B => '\u{203A}',
        0x9C => '\u{0153}',
        0x9E => '\u{017E}',
        0x9F => '\u{0178}',
        b => b as char,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(kind: &str, pairs: &[(usize, &str)]) -> String {
        let mut items = vec![String::new(); 16];
        items[0] = kind.into();
        for (index, value) in pairs {
            if *index >= items.len() {
                items.resize(index + 1, String::new());
            }
            items[*index] = (*value).into();
        }
        items.join("%")
    }

    fn sample() -> String {
        let build = fields(
            "0",
            &[
                (1, "build.example"),
                (2, "2222"),
                (3, "alex"),
                (5, "-1"),
                (7, "echo hi__PTVIRG__ true"),
                (14, r"_CurrentDrive_:\keys\id"),
            ],
        );
        let desk = fields("4", &[(1, "10.0.0.5"), (2, "3389")]);
        let box_session = fields(
            "0",
            &[
                (1, "box.example"),
                (2, "22"),
                (3, "<default>"),
                (8, "jump.example"),
                (9, "22"),
                (10, "gate"),
            ],
        );
        let files = fields("7", &[(1, "files.example"), (2, "22"), (3, "sam")]);
        format!(
            "[Bookmarks]\nSubRep=\nImgNum=42\nBuild=#109#{build}#MobaFont#0#note__DIEZE__1#255\nDesk=#91#{desk}\n[Bookmarks_1]\nSubRep=Work\\Lab\nBox=#109#{box_session}\nFiles=#140#{files}\n"
        )
    }

    #[test]
    fn ssh_sessions_come_across_and_other_kinds_do_not() {
        let mut file = SessionsFile::default();
        let report = apply_moba(&mut file, &sample(), "me");
        assert_eq!(report.sessions_added, 4, "{report:?}"); // build, jump, box, files
        assert_eq!(report.folders_added, 2);
        assert!(report.left_out.iter().any(|l| l.contains("remote desktop")));
        assert!(file.validate().is_ok(), "{:?}", file.validate());

        let build = file.sessions.iter().find(|s| s.name() == "Build").unwrap();
        match build {
            SavedSession::Ssh {
                host,
                port,
                user,
                auth,
                key_path,
                x11,
                startup,
                color,
                extras,
                folder,
                ..
            } => {
                assert_eq!(host, "build.example");
                assert_eq!(*port, 2222);
                assert_eq!(user, "alex");
                assert_eq!(*auth, SshAuth::Key);
                assert_eq!(key_path, r"C:\keys\id");
                assert!(*x11);
                assert_eq!(startup, "echo hi; true");
                assert_eq!(color, "#ff0000");
                assert_eq!(extras.note, "note#1");
                assert!(folder.is_empty());
            }
            _ => panic!(),
        }

        let box_session = file.sessions.iter().find(|s| s.name() == "Box").unwrap();
        match box_session {
            SavedSession::Ssh {
                user, jump, folder, ..
            } => {
                assert_eq!(user, "me");
                let hop = file.sessions.iter().find(|s| s.id() == jump).unwrap();
                assert_eq!(hop.name(), "jump.example jump");
                let folder_name = file.folders.iter().find(|f| f.id == *folder).unwrap();
                assert_eq!(folder_name.name, "Lab");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn the_same_server_is_not_added_twice() {
        let mut file = SessionsFile::default();
        apply_moba(&mut file, &sample(), "me");
        let again = apply_moba(&mut file, &sample(), "me");
        assert_eq!(again.sessions_added, 0);
        assert!(again.skipped >= 3);
    }

    #[test]
    fn a_file_without_bookmarks_is_explained() {
        let mut file = SessionsFile::default();
        let report = apply_moba(&mut file, "not a session file\n", "me");
        assert_eq!(report.sessions_added, 0);
        assert!(report.left_out[0].contains("Bookmarks"));
    }
}
