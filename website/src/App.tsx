import React, { useState } from "react";
import {
  BrandLockup,
  Button,
  Badge,
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  Alert,
  Tabs,
  TextField,
  Select,
} from "./ui";
import {
  Terminal,
  Shield,
  Layers,
  Lock,
  Compass,
  Copy,
  Check,
  Sun,
  Moon,
  Sparkles,
  Code2,
} from "lucide-react";

import inventoryData from "../../product-inventory.json";

interface InventoryProduct {
  id: string;
  title: string;
  source_directory: string;
  package_name: string;
  package_version: string;
  binary_name: string | null;
  product_kind: string;
  maturity: string;
  category: string;
  description: string;
  installable: boolean;
  release_targets: string[];
  dependencies: string[];
  verification: string;
}

interface ProductItem {
  id: string;
  title: string;
  category: "core" | "mesh" | "desktop" | "security";
  version: string;
  status: string;
  desc: string;
  command: string;
}

const CATEGORY_MAP: Record<string, "core" | "mesh" | "desktop" | "security"> = {
  sb: "core",
  core: "core",
  code: "mesh",
  db: "core",
  dns: "mesh",
  drive: "mesh",
  forge: "security",
  key: "security",
  mesh: "mesh",
  node: "core",
  ports: "core",
  proxy: "mesh",
  securenet: "mesh",
  shadow: "mesh",
  shell: "core",
  studio: "desktop",
  desktop: "desktop",
  netgrid: "desktop",
  ui: "desktop",
  workbench: "desktop",
  skully: "desktop",
};

const COMMAND_MAP: Record<string, string> = {
  sb: "sb doctor",
  core: "cargo test -p sb-core",
  code: "sb-code status",
  db: "sb-db status",
  dns: "sb-dns resolve localhost",
  drive: "sb-drive status",
  forge: "sb-forge --help",
  key: "sb key lease",
  mesh: "sb-mesh network list",
  node: "sb-node daemon",
  ports: "sb-ports scan",
  proxy: "sb proxy list",
  securenet: "sb-securenet status",
  shell: "sb-shell --version",
  studio: "npm run dev:studio",
  desktop: "npm run dev:desktop",
  netgrid: "npm run dev:netgrid",
  ui: "npm run build:ui",
  workbench: "npm run dev:workbench",
  skully: "skully --version",
};

function formatMaturity(maturity: string): string {
  switch (maturity) {
    case "prototype":
      return "Prototyp";
    case "implemented_not_releasevalidated":
      return "Pre-Release";
    default:
      return maturity;
  }
}

const PRODUCTS: ProductItem[] = (inventoryData.products as InventoryProduct[]).map(
  (prod) => ({
    id: prod.id,
    title: prod.title,
    category: CATEGORY_MAP[prod.id] || "core",
    version: `v${prod.package_version}`,
    status: formatMaturity(prod.maturity),
    desc: prod.description,
    command:
      COMMAND_MAP[prod.id] ||
      (prod.binary_name ? `${prod.binary_name} --help` : "cargo test"),
  })
);

export default function App() {
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string>("all");

  // Interactive UI Showcase state
  const [demoBtnBusy, setDemoBtnBusy] = useState(false);
  const [demoAlertVariant, setDemoAlertVariant] = useState<
    "info" | "success" | "warning" | "danger"
  >("info");
  const [demoInput, setDemoInput] = useState("callsign-node-alpha");
  const [demoSelect, setDemoSelect] = useState("ed25519");

  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    document.documentElement.setAttribute("data-sb-theme", next);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(text);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  const filteredProducts =
    selectedCategory === "all"
      ? PRODUCTS
      : PRODUCTS.filter((p) => p.category === selectedCategory);

  return (
    <div className={`site-wrapper ${theme === "light" ? "sbui-theme-light" : ""}`}>
      {/* Navigation */}
      <nav className="site-nav">
        <div className="site-container site-nav__inner">
          <BrandLockup product="Sovereign Suite" size="md" />

          <ul className="site-nav__links">
            <li>
              <a href="#manifest" className="site-nav__link">
                Manifest
              </a>
            </li>
            <li>
              <a href="#products" className="site-nav__link">
                Werkzeuge
              </a>
            </li>
            <li>
              <a href="#showcase" className="site-nav__link">
                UI-Designsystem
              </a>
            </li>
            <li>
              <a href="#architecture" className="site-nav__link">
                Architektur
              </a>
            </li>
            <li>
              <a href="#quickstart" className="site-nav__link">
                Quickstart
              </a>
            </li>
          </ul>

          <div className="site-nav__actions">
            <Button
              variant="ghost"
              size="sm"
              onClick={toggleTheme}
              aria-label="Theme umschalten"
            >
              {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={() => {
                document
                  .getElementById("quickstart")
                  ?.scrollIntoView({ behavior: "smooth" });
              }}
            >
              Terminal Quickstart
            </Button>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <header className="hero-section">
        <div className="site-container">
          <div className="hero-badge-wrap">
            <Badge variant="accent">
              <Sparkles size={14} style={{ marginRight: 6 }} />
              SOVEREIGN DEVELOPER SUITE // LOCAL-FIRST
            </Badge>
          </div>

          <h1 className="hero-title">
            Souveräne Werkzeuge. <br />
            <span className="accent">Klare Grenzen.</span> Nachprüfbare Sicherheit.
          </h1>

          <p className="hero-subtitle">
            Skulls &amp; Bones ist ein modulares Ökosystem autarker
            Entwickler-Werkzeuge. Behalte die vollständige Kontrolle über deinen
            Quellcode, deine Identitäten und deine Infrastruktur — ohne Lock-in
            und ohne proprietären Cloud-Zwang.
          </p>

          <div className="hero-cta-group">
            <Button
              variant="primary"
              size="md"
              onClick={() => {
                document
                  .getElementById("quickstart")
                  ?.scrollIntoView({ behavior: "smooth" });
              }}
            >
              <Terminal size={18} />
              CLI Installieren
            </Button>
            <Button
              variant="secondary"
              size="md"
              onClick={() => {
                document
                  .getElementById("products")
                  ?.scrollIntoView({ behavior: "smooth" });
              }}
            >
              <Layers size={18} />
              Suite Erkunden
            </Button>
            <Button
              variant="ghost"
              size="md"
              onClick={() => {
                document
                  .getElementById("showcase")
                  ?.scrollIntoView({ behavior: "smooth" });
              }}
            >
              <Code2 size={18} />
              @skulls-and-bones/ui Live
            </Button>
          </div>

          {/* Interactive Terminal Card */}
          <div className="terminal-card" id="quickstart">
            <div className="terminal-header">
              <div className="terminal-dots">
                <span className="terminal-dot" />
                <span className="terminal-dot" />
                <span className="terminal-dot" />
              </div>
              <span>sb-terminal // bash</span>
              <button
                style={{
                  background: "transparent",
                  border: "none",
                  color: "inherit",
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: 4,
                  fontSize: "0.75rem",
                }}
                onClick={() =>
                  copyToClipboard(
                    "cargo install --path tools/sb --bin sb && sb doctor"
                  )
                }
              >
                {copiedCmd ? (
                  <>
                    <Check size={14} color="var(--sb-ui-accent)" /> Kopiert
                  </>
                ) : (
                  <>
                    <Copy size={14} /> Kopieren
                  </>
                )}
              </button>
            </div>
            <div className="terminal-body">
              <div className="terminal-line">
                <span className="terminal-comment">
                  # 1. Suite Launcher lokal aus Quellcode installieren
                </span>
              </div>
              <div className="terminal-line">
                <span className="terminal-prompt">$</span>
                <span>cargo install --path tools/sb --bin sb</span>
              </div>
              <div className="terminal-line" style={{ marginTop: "0.5rem" }}>
                <span className="terminal-comment">
                  # 2. Integritäts- und Sicherheits-Audit ausführen
                </span>
              </div>
              <div className="terminal-line">
                <span className="terminal-prompt">$</span>
                <span>sb doctor</span>
              </div>
              <div
                className="terminal-line"
                style={{ marginTop: "0.5rem", color: "var(--sb-ui-accent)" }}
              >
                <span>
                  ► SYSTEM INTEGRITÄTS- &amp; SICHERHEITS-AUDIT [SB DOCTOR]
                </span>
              </div>
              <div className="terminal-line">
                <span>
                  1. Rust / Cargo Toolchain:          OPTIMAL (Lokaler Dev-Build)
                </span>
              </div>
              <div className="terminal-line">
                <span>
                  2. Root-Identität (~/.sb):          VERIFIZIERT (Ed25519)
                </span>
              </div>
              <div className="terminal-line">
                <span>
                  3. Secret-Verzeichnisse:            GESCHÜTZT (0700 / Isoliert)
                </span>
              </div>
              <div className="terminal-line">
                <span>
                  6. Suite Werkzeug-Integrität:       VOLLSTÄNDIG (13/13 Werkzeuge)
                </span>
              </div>
              <div
                className="terminal-line"
                style={{ color: "var(--sb-ui-success)" }}
              >
                <span>
                  7. Lokale Autarkie (Offline-Betrieb): AUTARK (Local-First / autark)
                </span>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Principles (Manifest) */}
      <section className="section" id="manifest">
        <div className="site-container">
          <div className="section-header">
            <span className="section-tag">Fundament &amp; Prinzipien</span>
            <h2 className="section-title">Technik vor Marketing-Versprechen</h2>
            <p className="section-desc">
              Wir unterscheiden klar zwischen bewiesenem Code, konkreten Zielen
              und offenen Forschungsfragen. Sicherheit entsteht nicht durch
              Superlative, sondern durch explizite Trust Boundaries.
            </p>
          </div>

          <div className="principles-grid">
            <div className="principle-card">
              <div className="principle-icon">
                <Shield size={20} />
              </div>
              <h3 className="principle-title">Souveränität</h3>
              <p className="principle-text">
                Quellcode, Identitäten, Schlüssel und Betriebsentscheidungen
                bleiben unter Kontrolle ihrer Betreiber. Replikation und
                Topologie sind offen, ohne Bindung an proprietäre Cloud-Anbieter.
              </p>
            </div>

            <div className="principle-card">
              <div className="principle-icon">
                <Layers size={20} />
              </div>
              <h3 className="principle-title">Modularität</h3>
              <p className="principle-text">
                Ein Tool, eine klare Zuständigkeit. Unabhängige Versionen und
                austauschbare Clients sind wertvoller als ein Sammelprogramm,
                das alle Funktionen selbst implementiert.
              </p>
            </div>

            <div className="principle-card">
              <div className="principle-icon">
                <Lock size={20} />
              </div>
              <h3 className="principle-title">Sicherheit ohne Superlative</h3>
              <p className="principle-text">
                Sicherheit entsteht aus expliziten Trust Boundaries, begrenzten
                Berechtigungen, sorgfältiger Fehlerbehandlung und
                nachvollziehbaren Tests statt pauschaler Garantien.
              </p>
            </div>

            <div className="principle-card">
              <div className="principle-icon">
                <Compass size={20} />
              </div>
              <h3 className="principle-title">Offenheit und Ehrlichkeit</h3>
              <p className="principle-text">
                Wir unterscheiden klar zwischen beschlossenem Ziel, vorhandenem
                Code, geprüftem Verhalten und Vorschlägen. Ein Feature wird
                nicht durch ein Badge real.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Product Suite Explorer */}
      <section className="section" id="products">
        <div className="site-container">
          <div className="section-header">
            <span className="section-tag">Das Ökosystem</span>
            <h2 className="section-title">Modulare Suite-Werkzeuge</h2>
            <p className="section-desc">
              Alle Komponenten sind unabhängig test- und baubar. Wähle eine
              Kategorie, um die einzelnen Tools zu inspizieren.
            </p>
          </div>

          <div
            style={{
              display: "flex",
              justifyContent: "center",
              marginBottom: "2.5rem",
            }}
          >
            <Tabs
              label="Produkt-Kategorien"
              items={[
                { value: "all", label: "Alle Werkzeuge" },
                { value: "core", label: "Core & CLI" },
                { value: "mesh", label: "Code & Mesh" },
                { value: "desktop", label: "Desktop Cockpits" },
                { value: "security", label: "Security & Keys" },
              ]}
              value={selectedCategory}
              onValueChange={setSelectedCategory}
            />
          </div>

          <div className="product-grid">
            {filteredProducts.map((prod) => (
              <Card key={prod.id} className="product-card">
                <CardHeader>
                  <div className="product-badge-row">
                    <Badge
                      variant={
                        prod.status === "Pre-Release" ? "accent" : "warning"
                      }
                    >
                      {prod.status}
                    </Badge>
                    <span
                      style={{
                        fontSize: "0.8rem",
                        fontFamily: "var(--sb-ui-font-mono)",
                        color: "var(--sb-ui-muted)",
                      }}
                    >
                      {prod.version}
                    </span>
                  </div>
                  <CardTitle>{prod.title}</CardTitle>
                  <CardDescription>{prod.desc}</CardDescription>
                </CardHeader>

                <CardContent style={{ marginTop: "auto" }}>
                  <div className="product-binary-code">
                    <span>$ {prod.command}</span>
                    <button
                      style={{
                        background: "transparent",
                        border: "none",
                        color: "inherit",
                        cursor: "pointer",
                      }}
                      onClick={() => copyToClipboard(prod.command)}
                      aria-label="Befehl kopieren"
                    >
                      {copiedCmd === prod.command ? (
                        <Check size={14} color="var(--sb-ui-accent)" />
                      ) : (
                        <Copy size={14} />
                      )}
                    </button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Live UI Showcase: @skulls-and-bones/ui */}
      <section className="section" id="showcase">
        <div className="site-container">
          <div className="section-header">
            <span className="section-tag">Konsistentes Design</span>
            <h2 className="section-title">
              @skulls-and-bones/ui Live Showcase
            </h2>
            <p className="section-desc">
              Diese gesamte Website und alle Suite-Tools (sb-desktop, sb-studio,
              sb-workbench, netgrid) teilen sich dieselbe React-Komponenten-Bibliothek
              und Design-Tokens. Probiere die Komponenten hier live aus:
            </p>
          </div>

          <div className="showcase-layout">
            {/* Interactive Sandbox */}
            <Card>
              <CardHeader>
                <CardTitle>Interaktive Sandbox</CardTitle>
                <CardDescription>
                  Verändere Werte, um die Reaktivität von sb-ui zu erleben.
                </CardDescription>
              </CardHeader>
              <CardContent
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: "1.25rem",
                }}
              >
                <TextField
                  label="Node Callsign (Identität)"
                  value={demoInput}
                  onChange={(e) => setDemoInput(e.target.value)}
                  helperText="Wird kryptographisch an den Root-Key gebunden"
                />

                <div className="sbui-field">
                  <label className="sbui-field__label">
                    Kryptographie-Algorithmus
                  </label>
                  <Select
                    items={[
                      { value: "ed25519", label: "Ed25519 (Modern & Schnell)" },
                      { value: "p256", label: "ECDSA P-256 (NIST-Standard)" },
                      { value: "argon2id", label: "Argon2id (Key Derivation)" },
                    ]}
                    value={demoSelect}
                    onValueChange={setDemoSelect}
                  />
                </div>

                <div>
                  <span
                    style={{
                      display: "block",
                      fontSize: "0.85rem",
                      fontWeight: 600,
                      marginBottom: "0.5rem",
                      color: "var(--sb-ui-text-soft)",
                    }}
                  >
                    Button-Zustände &amp; Busy-Spinner
                  </span>
                  <div
                    style={{
                      display: "flex",
                      gap: "0.5rem",
                      flexWrap: "wrap",
                    }}
                  >
                    <Button
                      variant="primary"
                      busy={demoBtnBusy}
                      onClick={() => {
                        setDemoBtnBusy(true);
                        setTimeout(() => setDemoBtnBusy(false), 1500);
                      }}
                    >
                      {demoBtnBusy ? "Initialisiere..." : "Primary Action"}
                    </Button>
                    <Button variant="secondary">Secondary</Button>
                    <Button variant="ghost">Ghost</Button>
                    <Button variant="danger">Danger</Button>
                  </div>
                </div>

                <div>
                  <span
                    style={{
                      display: "block",
                      fontSize: "0.85rem",
                      fontWeight: 600,
                      marginBottom: "0.5rem",
                      color: "var(--sb-ui-text-soft)",
                    }}
                  >
                    Alert-Varianten umschalten
                  </span>
                  <div
                    style={{
                      display: "flex",
                      gap: "0.5rem",
                      marginBottom: "0.75rem",
                    }}
                  >
                    {(["info", "success", "warning", "danger"] as const).map(
                      (v) => (
                        <Button
                          key={v}
                          size="sm"
                          variant={
                            demoAlertVariant === v ? "primary" : "secondary"
                          }
                          onClick={() => setDemoAlertVariant(v)}
                        >
                          {v}
                        </Button>
                      )
                    )}
                  </div>
                  <Alert
                    variant={demoAlertVariant}
                    title={`Alert Typ: ${demoAlertVariant}`}
                  >
                    Ausgewählter Node: <strong>{demoInput || "unbenannt"}</strong>{" "}
                    mit <strong>{demoSelect}</strong> Schutz.
                  </Alert>
                </div>
              </CardContent>
            </Card>

            {/* Design Tokens Preview */}
            <Card>
              <CardHeader>
                <CardTitle>Design-Tokens &amp; Palette</CardTitle>
                <CardDescription>
                  Taktische Farbwerte direkt aus der CSS-Variablen-Definition.
                </CardDescription>
              </CardHeader>
              <CardContent
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: "1rem",
                }}
              >
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "1fr 1fr",
                    gap: "0.75rem",
                  }}
                >
                  <div
                    style={{
                      padding: "0.75rem",
                      borderRadius: "var(--sb-ui-radius-sm)",
                      background: "var(--sb-ui-panel-raised)",
                      border: "1px solid var(--sb-ui-border)",
                    }}
                  >
                    <span
                      style={{
                        fontSize: "0.75rem",
                        color: "var(--sb-ui-muted)",
                      }}
                    >
                      --sb-ui-accent
                    </span>
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "0.5rem",
                        marginTop: 4,
                      }}
                    >
                      <span
                        style={{
                          width: 16,
                          height: 16,
                          borderRadius: 3,
                          background: "var(--sb-ui-accent)",
                        }}
                      />
                      <strong style={{ fontSize: "0.85rem" }}>
                        #52c7bd (Mint)
                      </strong>
                    </div>
                  </div>

                  <div
                    style={{
                      padding: "0.75rem",
                      borderRadius: "var(--sb-ui-radius-sm)",
                      background: "var(--sb-ui-panel-raised)",
                      border: "1px solid var(--sb-ui-border)",
                    }}
                  >
                    <span
                      style={{
                        fontSize: "0.75rem",
                        color: "var(--sb-ui-muted)",
                      }}
                    >
                      --sb-ui-brass
                    </span>
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "0.5rem",
                        marginTop: 4,
                      }}
                    >
                      <span
                        style={{
                          width: 16,
                          height: 16,
                          borderRadius: 3,
                          background: "var(--sb-ui-brass)",
                        }}
                      />
                      <strong style={{ fontSize: "0.85rem" }}>
                        #cfaa68 (Brass)
                      </strong>
                    </div>
                  </div>

                  <div
                    style={{
                      padding: "0.75rem",
                      borderRadius: "var(--sb-ui-radius-sm)",
                      background: "var(--sb-ui-panel-raised)",
                      border: "1px solid var(--sb-ui-border)",
                    }}
                  >
                    <span
                      style={{
                        fontSize: "0.75rem",
                        color: "var(--sb-ui-muted)",
                      }}
                    >
                      --sb-ui-ink
                    </span>
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "0.5rem",
                        marginTop: 4,
                      }}
                    >
                      <span
                        style={{
                          width: 16,
                          height: 16,
                          borderRadius: 3,
                          background: "var(--sb-ui-ink)",
                          border: "1px solid var(--sb-ui-border)",
                        }}
                      />
                      <strong style={{ fontSize: "0.85rem" }}>
                        #0b1113 (Deep Ink)
                      </strong>
                    </div>
                  </div>

                  <div
                    style={{
                      padding: "0.75rem",
                      borderRadius: "var(--sb-ui-radius-sm)",
                      background: "var(--sb-ui-panel-raised)",
                      border: "1px solid var(--sb-ui-border)",
                    }}
                  >
                    <span
                      style={{
                        fontSize: "0.75rem",
                        color: "var(--sb-ui-muted)",
                      }}
                    >
                      --sb-ui-success
                    </span>
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "0.5rem",
                        marginTop: 4,
                      }}
                    >
                      <span
                        style={{
                          width: 16,
                          height: 16,
                          borderRadius: 3,
                          background: "var(--sb-ui-success)",
                        }}
                      />
                      <strong style={{ fontSize: "0.85rem" }}>
                        #72c9a1 (Emerald)
                      </strong>
                    </div>
                  </div>
                </div>

                <div
                  style={{
                    padding: "1rem",
                    borderRadius: "var(--sb-ui-radius-sm)",
                    background: "var(--sb-ui-panel-raised)",
                    border: "1px solid var(--sb-ui-border)",
                    fontFamily: "var(--sb-ui-font-mono)",
                    fontSize: "0.8rem",
                  }}
                >
                  <p
                    style={{
                      margin: "0 0 0.5rem",
                      color: "var(--sb-ui-accent)",
                    }}
                  >
                    // UI Workbench Integration
                  </p>
                  <p style={{ margin: 0, color: "var(--sb-ui-text-soft)" }}>
                    Starte das eigenständige Desktop-Tool zur Live-Bearbeitung
                    aller Farben und Layout-Tokens:
                  </p>
                  <p
                    style={{
                      margin: "0.5rem 0 0",
                      color: "var(--sb-ui-text)",
                    }}
                  >
                    $ npm run dev:workbench
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* Architecture Showcase */}
      <section className="section" id="architecture">
        <div className="site-container">
          <div className="section-header">
            <span className="section-tag">Netzwerk- &amp; Zielbild</span>
            <h2 className="section-title">Gehärtete Infrastruktur</h2>
            <p className="section-desc">
              Das reale Zielbild für Dev-Server und Workstations. Public-Zone und
              Mesh-Zone sind strikt voneinander getrennt.
            </p>
          </div>

          <div className="arch-diagram">
            <pre style={{ margin: 0 }}>
{`                 Internet
                    │
    ┌───────────────┼──────────────────────────────┐
    │ TCP 22        │ TCP 80/443        UDP 58888  │   ← Einzige offene Ports (UFW)
    │ SSH           │ sb-proxy          sb-node    │
    │ (Nur Ed25519) │ (User: sb-public) Anchor     │
    └──────┬────────┴──────┬────────────────┬──────┘
           │               │                │
      Admin-Zugang   Public-Zone     Multi-Mesh-Dispatcher
                     (Read-Only)     ├─ <MESH_PUBLIC>  10.241.0.0/16
                                     └─ <MESH_DEV>     10.240.0.0/16
                                            │ Explizite Route (Default-Deny)
                                            ▼
                                   127.0.0.1:58832  sb-code syncd`}
            </pre>
          </div>

          <div
            style={{
              marginTop: "2rem",
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
              gap: "1.5rem",
            }}
          >
            <Card>
              <CardHeader>
                <CardTitle>Public-Zone (sb-proxy &amp; sb-public)</CardTitle>
                <CardDescription>
                  Das Suite-eigene <code>sb-proxy</code> läuft unter dem
                  isolierten Systemkonto <code>sb-public</code> und serviert
                  Web-Assets und Release-Binaries mit automatischem ACME
                  Let's Encrypt TLS (HTTP/2).
                </CardDescription>
              </CardHeader>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Dev-Zone (sb-node &amp; sb-code)</CardTitle>
                <CardDescription>
                  Der Code-Synchronisations-Daemon lauscht ausschließlich auf
                  Loopback (Port 58832) und ist nur über autorisierte Mesh-Routen
                  erreichbar.
                </CardDescription>
              </CardHeader>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>1-Befehl Provisioning</CardTitle>
                <CardDescription>
                  Mit{" "}
                  <code>
                    sb server provision &lt;host&gt; --pubkey &lt;file&gt;
                  </code>{" "}
                  wird ein frischer Linux VPS in 3 Minuten vollautomatisch
                  gehärtet.
                </CardDescription>
              </CardHeader>
            </Card>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="site-footer">
        <div className="site-container footer-inner">
          <div className="footer-meta">
            <BrandLockup size="sm" />
            <p style={{ margin: "0.5rem 0 0", fontSize: "0.82rem" }}>
              Autarke Entwickler-Infrastruktur &amp; Taktische Werkzeuge.
            </p>
            <p style={{ margin: 0, fontSize: "0.75rem" }}>
              &copy; {new Date().getFullYear()} Skulls &amp; Bones.
              MIT-Lizenz &bull; Souveräne Software.
            </p>
          </div>

          <div className="footer-links">
            <a href="#manifest" className="footer-link">
              Manifest
            </a>
            <a href="#products" className="footer-link">
              Werkzeuge
            </a>
            <a href="#showcase" className="footer-link">
              Designsystem
            </a>
            <a href="#architecture" className="footer-link">
              Architektur
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}
