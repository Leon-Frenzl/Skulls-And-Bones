//! `sb server provision <host>` — fresh VPS -> hardened, mesh-ready node in one idempotent run.
//!
//! Functional core: `generate_provision_script` is a pure string builder (unit-tested).
//! Shell: `handle_server_provision` validates input and pipes the script into `ssh ... bash -s`.

use colored::*;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::commands::fleet::{is_valid_host, is_valid_nodename, is_valid_username};

pub struct ProvisionPlan<'a> {
    pub admin_user: &'a str,
    pub admin_pubkey: &'a str,
    pub ssh_port: u16,
    pub mesh_names: &'a [String],
    pub remote_bin_dir: Option<&'a str>,
}

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisionError {
    InvalidHost(String),
    InvalidUser { label: &'static str, user: String },
    InvalidMeshName(String),
    KeyNotFound,
    InvalidPublicKey(String),
    KeyReadError { path: PathBuf, error: String },
    ToolNotFound { tool: &'static str, details: String },
    RemotePreparationFailed,
    UploadFailed,
    StdinUnavailable,
    ExecutionFailed(String),
    ProcessFailed,
}

impl fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHost(h) => write!(f, "Ungültiger Host: {h}."),
            Self::InvalidUser { label, user } => write!(f, "Ungültiger {label}: {user}."),
            Self::InvalidMeshName(m) => write!(f, "Ungültiger Mesh-Name '{m}'."),
            Self::KeyNotFound => write!(f, "Kein öffentlicher Schlüssel gefunden (--pubkey)."),
            Self::InvalidPublicKey(msg) => write!(
                f,
                "Ungültiger oder unsicherer öffentlicher SSH-Schlüssel: {msg}"
            ),
            Self::KeyReadError { path, error } => {
                write!(f, "Schlüssel {} nicht lesbar: {error}", path.display())
            }
            Self::ToolNotFound { tool, details } => {
                write!(f, "Kein OpenSSH `{tool}` gefunden. {details}")
            }
            Self::RemotePreparationFailed => write!(f, "Remote-Vorbereitung fehlgeschlagen."),
            Self::UploadFailed => write!(f, "Upload der Binaries fehlgeschlagen."),
            Self::StdinUnavailable => write!(f, "stdin nicht verfügbar."),
            Self::ExecutionFailed(err) => write!(f, "Befehlsausführung fehlgeschlagen: {err}"),
            Self::ProcessFailed => write!(f, "Provisioning fehlgeschlagen."),
        }
    }
}

impl std::error::Error for ProvisionError {}

// CVE-Threat: Shell injection through host/user/key/mesh values interpolated into a root script.
// Analysis: Every interpolated value ends up in a root shell.
// Hardening: Strict allow-list validation here; the script itself single-quotes nothing user-supplied
//            beyond these validated tokens (pubkey is validated to a safe charset below).
pub fn validate_pubkey(key: &str) -> Result<(), ProvisionError> {
    let k = key.trim();
    let ok_prefix = [
        "ssh-ed25519 ",
        "ssh-rsa ",
        "ecdsa-sha2-nistp256 ",
        "sk-ssh-ed25519@openssh.com ",
    ]
    .iter()
    .any(|p| k.starts_with(p));
    let ok_chars = k
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || " +/=@.-_".contains(c));
    if ok_prefix && ok_chars && !k.contains('\n') {
        Ok(())
    } else {
        Err(ProvisionError::InvalidPublicKey(
            "Format muss ssh-ed25519, ssh-rsa, ecdsa oder sk-ssh-ed25519 entsprechen.".into(),
        ))
    }
}

pub fn generate_provision_script(p: &ProvisionPlan) -> String {
    let meshes = p.mesh_names.join(" ");
    let install_bins = match p.remote_bin_dir {
        Some(dir) => format!(
            "for b in {dir}/*; do install -m 0755 -o root -g root \"$b\" /usr/local/bin/$(basename \"$b\"); sha256sum /usr/local/bin/$(basename \"$b\"); done"
        ),
        None => "echo '[SB] Keine Binaries übergeben (--binaries); erwarte sb-node/sb-code in /usr/local/bin'".to_string(),
    };
    format!(
        r#"set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
ADMIN='{user}'
SSH_PORT={port}

echo '[SB] 1/6 Pakete'
apt-get update -qq
apt-get install -y -qq ufw fail2ban unattended-upgrades curl ca-certificates >/dev/null

echo '[SB] 2/6 Admin-User + Key-Login'
id -u "$ADMIN" >/dev/null 2>&1 || adduser --disabled-password --gecos '' "$ADMIN"
install -d -m 0700 -o "$ADMIN" -g "$ADMIN" "/home/$ADMIN/.ssh"
AK="/home/$ADMIN/.ssh/authorized_keys"
touch "$AK"
grep -qxF '{key}' "$AK" || echo '{key}' >> "$AK"
chown "$ADMIN:$ADMIN" "$AK"; chmod 0600 "$AK"
echo "$ADMIN ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/90-sb-$ADMIN"
chmod 0440 "/etc/sudoers.d/90-sb-$ADMIN"
visudo -cf "/etc/sudoers.d/90-sb-$ADMIN" >/dev/null

echo '[SB] 3/6 SSH härten (nur wenn Key-Login des Admins vorhanden)'
[ -s "$AK" ] || {{ echo 'Abbruch: kein Key hinterlegt'; exit 1; }}
cat > /etc/ssh/sshd_config.d/00-sb-hardening.conf <<EOF
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowUsers $ADMIN
MaxAuthTries 3
LoginGraceTime 20
X11Forwarding no
EOF
sshd -t
systemctl reload ssh || systemctl reload sshd

echo '[SB] 4/6 Firewall'
ufw --force reset >/dev/null
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow "$SSH_PORT"/tcp >/dev/null
ufw allow 58888/udp >/dev/null
ufw --force enable >/dev/null
systemctl enable --now fail2ban >/dev/null 2>&1

echo '[SB] 5/6 Binaries'
{install_bins}

echo '[SB] 6/6 Gehärtete Units'
mkdir -p "/home/$ADMIN/.sb-mesh"; chown -R "$ADMIN:$ADMIN" "/home/$ADMIN/.sb-mesh"
HARDEN='NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
SystemCallArchitectures=native
CapabilityBoundingSet=
AmbientCapabilities='
if [ -x /usr/local/bin/sb-node ]; then
cat > /etc/systemd/system/sb-node.service <<EOF
[Unit]
Description=S&B Node Daemon
After=network-online.target
Wants=network-online.target
[Service]
User=$ADMIN
ExecStart=/usr/local/bin/sb-node daemon
Restart=always
RestartSec=5
ReadWritePaths=/home/$ADMIN/.sb-mesh /home/$ADMIN/.sb
$HARDEN
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now sb-node
fi
for m in {meshes}; do
  [ -x /usr/local/bin/sb-mesh ] && sudo -u "$ADMIN" /usr/local/bin/sb-mesh bootstrap --headless -n "$m" -a "127.0.0.1:58888" || true
done
echo '[SB] Provisioning abgeschlossen.'
"#,
        user = p.admin_user,
        port = p.ssh_port,
        key = p.admin_pubkey.trim(),
        install_bins = install_bins,
        meshes = meshes,
    )
}

fn find_openssh(bin: &str) -> Option<PathBuf> {
    if let Ok(over) = std::env::var("SB_OPENSSH_DIR") {
        let p = Path::new(&over).join(bin);
        if p.exists() {
            return Some(p);
        }
    }
    which::which_all(bin).ok()?.find(|p| {
        let s = p.to_string_lossy().to_lowercase();
        !s.contains(".cargo")
    })
}

#[allow(clippy::too_many_arguments)]
pub fn handle_server_provision(
    host: &str,
    user: &str,
    admin: &str,
    pubkey_file: Option<PathBuf>,
    port: u16,
    meshes: Vec<String>,
    binaries: Option<PathBuf>,
    print_script: bool,
) -> Result<(), ProvisionError> {
    if !is_valid_host(host) {
        return Err(ProvisionError::InvalidHost(host.to_string()));
    }
    for (label, v) in [("Login-User", user), ("Admin-User", admin)] {
        if !is_valid_username(v) {
            return Err(ProvisionError::InvalidUser {
                label,
                user: v.to_string(),
            });
        }
    }
    if let Some(m) = meshes.iter().find(|m| !is_valid_nodename(m)) {
        return Err(ProvisionError::InvalidMeshName(m.to_string()));
    }

    let key_path = pubkey_file
        .or_else(|| dirs::home_dir().map(|h| h.join(".ssh").join("id_ed25519.pub")))
        .ok_or(ProvisionError::KeyNotFound)?;
    let pubkey = std::fs::read_to_string(&key_path).map_err(|e| ProvisionError::KeyReadError {
        path: key_path.clone(),
        error: e.to_string(),
    })?;
    validate_pubkey(&pubkey)?;

    let remote_dir = binaries.as_ref().map(|_| "/tmp/sb-provision-bin");
    let script = generate_provision_script(&ProvisionPlan {
        admin_user: admin,
        admin_pubkey: &pubkey,
        ssh_port: port,
        mesh_names: &meshes,
        remote_bin_dir: remote_dir,
    });

    if print_script {
        print!("{script}");
        return Ok(());
    }

    let ssh = find_openssh("ssh.exe")
        .or_else(|| find_openssh("ssh"))
        .ok_or(ProvisionError::ToolNotFound {
            tool: "ssh",
            details: "Setze SB_OPENSSH_DIR.".into(),
        })?;
    let target = format!("{user}@{host}");
    let port_s = port.to_string();
    let base = [
        "-p",
        port_s.as_str(),
        "-o",
        "StrictHostKeyChecking=accept-new",
    ];

    if let Some(dir) = &binaries {
        let scp = find_openssh("scp.exe")
            .or_else(|| find_openssh("scp"))
            .ok_or(ProvisionError::ToolNotFound {
                tool: "scp",
                details: "OpenSSH scp binary fehlt.".into(),
            })?;
        let prep = Command::new(&ssh)
            .args(base)
            .arg(&target)
            .arg("rm -rf /tmp/sb-provision-bin && mkdir -m 0700 /tmp/sb-provision-bin")
            .status()
            .map_err(|e| ProvisionError::ExecutionFailed(e.to_string()))?;
        if !prep.success() {
            return Err(ProvisionError::RemotePreparationFailed);
        }
        let files: Vec<_> = std::fs::read_dir(dir)
            .map_err(|e| ProvisionError::ExecutionFailed(e.to_string()))?
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect();
        let st = Command::new(&scp)
            .args(["-P", &port_s, "-o", "StrictHostKeyChecking=accept-new"])
            .args(&files)
            .arg(format!("{target}:/tmp/sb-provision-bin/"))
            .status()
            .map_err(|e| ProvisionError::ExecutionFailed(e.to_string()))?;
        if !st.success() {
            return Err(ProvisionError::UploadFailed);
        }
    }

    println!("  {} Provisioniere {} ...", "►".bright_cyan(), host);
    let mut child = Command::new(&ssh)
        .args(base)
        .arg(&target)
        .arg(if user == "root" {
            "bash -s"
        } else {
            "sudo bash -s"
        })
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| ProvisionError::ExecutionFailed(e.to_string()))?;
    child
        .stdin
        .take()
        .ok_or(ProvisionError::StdinUnavailable)?
        .write_all(script.as_bytes())
        .map_err(|e| ProvisionError::ExecutionFailed(e.to_string()))?;
    let status = child
        .wait()
        .map_err(|e| ProvisionError::ExecutionFailed(e.to_string()))?;
    if status.success() {
        println!(
            "  {} Fertig. Login künftig: ssh -p {} {}@{}",
            "✓".bright_green().bold(),
            port,
            admin,
            host
        );
        Ok(())
    } else {
        Err(ProvisionError::ProcessFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_is_hardened_and_ordered() {
        let meshes = vec!["dev".to_string()];
        let s = generate_provision_script(&ProvisionPlan {
            admin_user: "ops",
            admin_pubkey: "ssh-ed25519 AAAA test@host",
            ssh_port: 22,
            mesh_names: &meshes,
            remote_bin_dir: None,
        });
        assert!(s.contains("PasswordAuthentication no"));
        assert!(s.contains("NoNewPrivileges=yes"));
        // key must be installed before root login/password auth is disabled
        assert!(s.find("authorized_keys").unwrap() < s.find("PermitRootLogin no").unwrap());
        assert!(s.contains("sshd -t"));
    }

    #[test]
    fn pubkey_validation_rejects_injection() {
        assert!(validate_pubkey("ssh-ed25519 AAAAC3 me@x").is_ok());
        assert!(validate_pubkey("ssh-ed25519 AAAA'; rm -rf / #").is_err());
        assert!(validate_pubkey("ssh-ed25519 AAAA\nssh-rsa B").is_err());
        assert!(validate_pubkey("garbage").is_err());
    }
}
