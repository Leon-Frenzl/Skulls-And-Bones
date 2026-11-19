use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::TcpListener;

/// Konfiguration für anpassbare Auth-UI-Seiten
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    pub title: String,
    pub subtitle: String,
    pub primary_color: String,
    pub background_color: String,
    pub card_background: String,
    pub text_color: String,
    pub border_color: String,
    pub logo_text: String,
    pub api_login_endpoint: String,
    pub api_register_endpoint: String,
    pub api_totp_endpoint: String,
    pub enable_totp: bool,
    pub enable_register: bool,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            title: "SKULLS & BONES".to_string(),
            subtitle: "Sovereign Authentication Gateway".to_string(),
            primary_color: "#00f0ff".to_string(), // Cyber Cyan
            background_color: "#0b0b0d".to_string(), // Tiefes Schwarz
            card_background: "#141418".to_string(), // Anthrazit
            text_color: "#e6e6e6".to_string(),
            border_color: "#26262e".to_string(),
            logo_text: "S&B AUTH".to_string(),
            api_login_endpoint: "/api/auth/login".to_string(),
            api_register_endpoint: "/api/auth/register".to_string(),
            api_totp_endpoint: "/api/auth/totp/verify".to_string(),
            enable_totp: true,
            enable_register: true,
        }
    }
}

/// Generiert eine vollständige, autarke und reaktive HTML/CSS/JS-Login-Seite
pub fn render_login_page(cfg: &UiConfig) -> String {
    format!(
        r#"<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title} — Login</title>
  <style>
    :root {{
      --sba-primary: {primary_color};
      --sba-bg: {background_color};
      --sba-card: {card_background};
      --sba-text: {text_color};
      --sba-border: {border_color};
      --sba-danger: #ff3366;
      --sba-success: #00ff88;
      --sba-font: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background-color: var(--sba-bg);
      color: var(--sba-text);
      font-family: var(--sba-font);
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 1.5rem;
    }}
    .auth-card {{
      background: var(--sba-card);
      border: 1px solid var(--sba-border);
      border-radius: 8px;
      width: 100%;
      max-width: 420px;
      padding: 2.25rem;
      box-shadow: 0 8px 32px rgba(0,0,0,0.6);
      position: relative;
      overflow: hidden;
    }}
    .auth-card::before {{
      content: "";
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 3px;
      background: var(--sba-primary);
    }}
    .auth-header {{
      text-align: center;
      margin-bottom: 2rem;
    }}
    .auth-logo {{
      display: inline-block;
      font-weight: 800;
      letter-spacing: 2px;
      color: var(--sba-primary);
      border: 1px solid var(--sba-primary);
      padding: 0.25rem 0.75rem;
      border-radius: 4px;
      margin-bottom: 1rem;
      font-size: 0.85rem;
    }}
    .auth-title {{
      font-size: 1.25rem;
      font-weight: 700;
      letter-spacing: 1px;
      margin-bottom: 0.25rem;
    }}
    .auth-subtitle {{
      font-size: 0.8rem;
      opacity: 0.6;
    }}
    .tabs {{
      display: flex;
      border-bottom: 1px solid var(--sba-border);
      margin-bottom: 1.5rem;
    }}
    .tab {{
      flex: 1;
      text-align: center;
      padding: 0.6rem;
      font-size: 0.85rem;
      font-weight: 600;
      color: var(--sba-text);
      background: transparent;
      border: none;
      cursor: pointer;
      opacity: 0.6;
      border-bottom: 2px solid transparent;
      transition: all 0.2s;
    }}
    .tab.active {{
      opacity: 1;
      color: var(--sba-primary);
      border-bottom-color: var(--sba-primary);
    }}
    .form-group {{
      margin-bottom: 1.25rem;
    }}
    label {{
      display: block;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 0.4rem;
      opacity: 0.8;
    }}
    input {{
      width: 100%;
      background: rgba(0,0,0,0.3);
      border: 1px solid var(--sba-border);
      color: var(--sba-text);
      font-family: inherit;
      padding: 0.75rem 0.9rem;
      border-radius: 4px;
      font-size: 0.9rem;
      transition: border 0.2s;
    }}
    input:focus {{
      outline: none;
      border-color: var(--sba-primary);
    }}
    .btn {{
      width: 100%;
      background: var(--sba-primary);
      color: #000;
      font-family: inherit;
      font-weight: 700;
      letter-spacing: 1px;
      text-transform: uppercase;
      padding: 0.85rem;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      margin-top: 0.5rem;
      transition: opacity 0.2s;
    }}
    .btn:hover {{ opacity: 0.9; }}
    .btn:disabled {{ opacity: 0.5; cursor: not-allowed; }}
    .toast {{
      margin-top: 1rem;
      padding: 0.75rem;
      border-radius: 4px;
      font-size: 0.8rem;
      display: none;
    }}
    .toast.error {{
      display: block;
      background: rgba(255, 51, 102, 0.15);
      border: 1px solid var(--sba-danger);
      color: var(--sba-danger);
    }}
    .toast.success {{
      display: block;
      background: rgba(0, 255, 136, 0.15);
      border: 1px solid var(--sba-success);
      color: var(--sba-success);
    }}
    .totp-input {{
      letter-spacing: 6px;
      font-size: 1.25rem;
      text-align: center;
    }}
  </style>
</head>
<body>
  <div class="auth-card">
    <div class="auth-header">
      <div class="auth-logo">{logo_text}</div>
      <h1 class="auth-title">{title}</h1>
      <p class="auth-subtitle">{subtitle}</p>
    </div>

    <div class="tabs">
      <button class="tab active" onclick="switchTab('login')">Anmelden</button>
      <button class="tab" onclick="switchTab('register')">Registrieren</button>
      <button class="tab" onclick="switchTab('totp')">2FA / TOTP</button>
    </div>

    <!-- LOGIN FORM -->
    <form id="form-login" onsubmit="handleLogin(event)">
      <div class="form-group">
        <label for="login-username">Benutzername / Identität</label>
        <input id="login-username" type="text" required placeholder="z. B. leonf" autocomplete="username">
      </div>
      <div class="form-group">
        <label for="login-password">Passwort</label>
        <input id="login-password" type="password" required placeholder="••••••••••••" autocomplete="current-password">
      </div>
      <button id="btn-login" class="btn" type="submit">Authentifizieren</button>
    </form>

    <!-- REGISTER FORM -->
    <form id="form-register" style="display:none;" onsubmit="handleRegister(event)">
      <div class="form-group">
        <label for="reg-username">Neuer Benutzername</label>
        <input id="reg-username" type="text" required placeholder="z. B. dev-alice" autocomplete="username">
      </div>
      <div class="form-group">
        <label for="reg-password">Passwort festlegen</label>
        <input id="reg-password" type="password" required placeholder="••••••••••••" autocomplete="new-password">
      </div>
      <div class="form-group">
        <label for="reg-password-confirm">Passwort bestätigen</label>
        <input id="reg-password-confirm" type="password" required placeholder="••••••••••••" autocomplete="new-password">
      </div>
      <button id="btn-register" class="btn" type="submit">Konto erstellen</button>
    </form>

    <!-- TOTP FORM -->
    <form id="form-totp" style="display:none;" onsubmit="handleTotp(event)">
      <div class="form-group">
        <label for="totp-code">6-Stelliger Sicherheitscode</label>
        <input id="totp-code" class="totp-input" type="text" maxlength="6" pattern="[0-9]{{6}}" required placeholder="000000" autocomplete="one-time-code">
      </div>
      <button id="btn-totp" class="btn" type="submit">Code Verifizieren</button>
    </form>

    <div id="toast" class="toast"></div>
  </div>

  <script>
    function showToast(msg, isSuccess) {{
      const t = document.getElementById('toast');
      t.className = 'toast ' + (isSuccess ? 'success' : 'error');
      t.innerText = msg;
    }}

    function switchTab(tab) {{
      document.querySelectorAll('.tab').forEach((el, idx) => {{
        el.classList.toggle('active', (tab === 'login' && idx === 0) || (tab === 'register' && idx === 1) || (tab === 'totp' && idx === 2));
      }});
      document.getElementById('form-login').style.display = tab === 'login' ? 'block' : 'none';
      document.getElementById('form-register').style.display = tab === 'register' ? 'block' : 'none';
      document.getElementById('form-totp').style.display = tab === 'totp' ? 'block' : 'none';
      document.getElementById('toast').style.display = 'none';
    }}

    async function handleLogin(e) {{
      e.preventDefault();
      const btn = document.getElementById('btn-login');
      btn.disabled = true;
      try {{
        const res = await fetch('{api_login_endpoint}', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{
            username: document.getElementById('login-username').value,
            password: document.getElementById('login-password').value
          }})
        }});
        const data = await res.json();
        if (res.ok) {{
          showToast('Erfolgreich authentifiziert! Token erhalten.', true);
          if (data.access_token) {{
            localStorage.setItem('sbt_token', data.access_token);
          }}
          if (data.mfa_required) switchTab('totp');
        }} else {{
          showToast(data.message || 'Authentifizierung fehlgeschlagen', false);
        }}
      }} catch (err) {{
        showToast('Verbindungsfehler zum Auth-Gateway', false);
      }} finally {{
        btn.disabled = false;
      }}
    }}

    async function handleRegister(e) {{
      e.preventDefault();
      const p1 = document.getElementById('reg-password').value;
      const p2 = document.getElementById('reg-password-confirm').value;
      if (p1 !== p2) {{
        showToast('Die Passwörter stimmen nicht überein!', false);
        return;
      }}
      const btn = document.getElementById('btn-register');
      btn.disabled = true;
      try {{
        const res = await fetch('{api_register_endpoint}', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{
            username: document.getElementById('reg-username').value,
            password: p1
          }})
        }});
        const data = await res.json();
        if (res.ok) {{
          showToast('Konto erfolgreich erstellt! Bitte anmelden.', true);
          setTimeout(() => switchTab('login'), 1500);
        }} else {{
          showToast(data.message || 'Registrierung fehlgeschlagen', false);
        }}
      }} catch (err) {{
        showToast('Verbindungsfehler', false);
      }} finally {{
        btn.disabled = false;
      }}
    }}

    async function handleTotp(e) {{
      e.preventDefault();
      const btn = document.getElementById('btn-totp');
      btn.disabled = true;
      try {{
        const res = await fetch('{api_totp_endpoint}', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{
            code: document.getElementById('totp-code').value,
            token: localStorage.getItem('sbt_token')
          }})
        }});
        const data = await res.json();
        if (res.ok) {{
          showToast('2FA erfolgreich bestätigt!', true);
        }} else {{
          showToast(data.message || 'Ungültiger Code', false);
        }}
      }} catch (err) {{
        showToast('Verbindungsfehler', false);
      }} finally {{
        btn.disabled = false;
      }}
    }}
  </script>
</body>
</html>"#,
        title = cfg.title,
        subtitle = cfg.subtitle,
        primary_color = cfg.primary_color,
        background_color = cfg.background_color,
        card_background = cfg.card_background,
        text_color = cfg.text_color,
        border_color = cfg.border_color,
        logo_text = cfg.logo_text,
        api_login_endpoint = cfg.api_login_endpoint,
        api_register_endpoint = cfg.api_register_endpoint,
        api_totp_endpoint = cfg.api_totp_endpoint,
    )
}

/// Startet einen autarken lokalen Vorschau-Server (ohne externe Framework-Abhängigkeiten)
pub fn serve_preview(port: u16, cfg: &UiConfig) -> std::io::Result<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))?;
    let html = render_login_page(cfg);
    let html_bytes = html.as_bytes();

    println!(
        "  ► S&B Auth UI Vorschau-Server aktiv: http://127.0.0.1:{}",
        port
    );
    println!("  i Drücke Ctrl+C zum Beenden.");

    for mut stream in listener.incoming().flatten() {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf);

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            html_bytes.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.write_all(html_bytes);
        let _ = stream.flush();
    }
    Ok(())
}
