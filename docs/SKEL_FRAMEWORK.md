# Skel — Arbeitsdefinition und Architekturprinzipien (Ausgegliedert)

> **Status:** Ausgegliedert / Historische Rahmenspezifikation (Nicht Teil der 14 Core-Tools)  
> **Hinweis:** `skel` wurde im Zuge der 14-Core-Konsolidierung aus der aktiven Core-Suite ausgegliedert. Dieses Dokument verbleibt ausschließlich als historische Referenz.

## Definition

**Skel ist ein Rust-basiertes, servergetriebenes Frontend-Framework, mit dem Entwickler Benutzeroberflächen aus explizit gewählten, benannten Komponenten und Aktionen zusammensetzen.** Es soll die Lesbarkeit linearer Builder-Pipelines mit der Kontrolle eines bewusst entworfenen UIs verbinden: Der Entwickler bestimmt, welche Inhalte und Aktionen erscheinen, wie sie fachlich reagieren und welche Berechtigungen dafür erforderlich sind. Skel soll unnötige Layout-Verschachtelung aus dem Anwendungscode heraushalten, ohne Struktur, Verhalten oder Gestaltung automatisch aus Domain-Daten abzuleiten.

Das Framework trennt dabei drei Verantwortlichkeiten:

- **Anwendung und Domain-Code** wählen die anzuzeigenden Werte, Komponenten und Aktionen ausdrücklich aus.
- **Skel-Komponenten und Builder** machen diese Auswahl als benannte, wiederverwendbare Bausteine komponierbar.
- **Stylesheets** bestimmen die visuelle Darstellung und Anordnung, nicht die fachliche Funktion einer Aktion oder die Autorisierung.

Die Laufzeit projiziert die explizit komponierte View in eine semantische Darstellung, rendert HTML und kann Änderungen über ein Wire-Protokoll übertragen. Interaktionen werden als Intents an den Server gesendet; dort müssen Berechtigungen und weitere fachliche Vorbedingungen geprüft werden. ETags können den dem Client bekannten Komponentenstand kennzeichnen und veraltete Änderungen erkennen helfen. Ein ETag ist weder ein Berechtigungsnachweis noch ein Ersatz für serverseitige Validierung.

Der Server ist der Standardpfad für Rendering, Anwendungszustand und fachliche Aktionen. Wo unmittelbares oder browserlokales Verhalten nötig ist, darf eine View ausdrücklich eine **Client-Island** einbinden. Jede Island hat einen begrenzten Zuständigkeitsbereich und einen dokumentierten Eingabe-/Ausgabevertrag; sie darf keinen parallelen, unsichtbaren Zustand für die restliche Anwendung etablieren. Ohne JavaScript sollen Inhalt und zentrale Navigation weiterhin benutzbar bleiben, soweit die jeweilige Funktion das ermöglicht.

## Entwickler-Modell

### Explizite Komposition statt Layout-Schachtelung

Eine View soll in verständliche, benannte Teilansichten zerlegt werden: beispielsweise Header, Metriken, Formular und Tabelle. Die abschließende Komposition bleibt als lineare Liste dieser Bausteine lesbar. Komponenten dürfen intern eine Struktur besitzen; Skel soll Entwickler aber nicht zwingen, jedes visuelle Detail als verschachtelte Folge anonymer Container im Anwendungscode auszudrücken.

### Kontrolle statt impliziter UI-Magie

Skel leitet nicht automatisch Benutzeroberflächen aus Struct-Feldern, Methoden oder Makro-Konventionen ab. Ein Feld wird nicht allein deshalb angezeigt, weil es in einem Domain-Typ existiert; eine Methode wird nicht automatisch zu einem Button. Entwickler wählen Inhalte und Aktionen aus und entscheiden über ihre Platzierung und Gestaltung. Makros und Generatoren dürfen diese explizite Kontrolle nicht durch überraschende UI- oder Berechtigungsentscheidungen ersetzen.

### Verhalten und Darstellung bleiben getrennt

Ein Stylesheet darf Farben, Typografie, Abstände, Grid-/Flex-Anordnung und visuelle Varianten steuern. Es darf nicht festlegen, welche fachlichen Aktionen existieren, Berechtigungen erteilen oder serverseitige Vorbedingungen umgehen. Umgekehrt soll fachlicher Rust-Code nicht mit Präsentationsdetails überladen werden.

### Autorisierung wird serverseitig durchgesetzt

Die Oberfläche kann geschützte Aktionen ausblenden oder deaktiviert darstellen, um den verfügbaren Zustand verständlich zu machen. Diese Darstellung ist nur UX. Jeder Intent muss bei seiner Ausführung im vertrauenswürdigen Serverpfad authentisiert und autorisiert sowie gegen fachliche Invarianten geprüft werden. Ein clientseitiger Guard, eine Session-ID oder ein ETag gewährt für sich genommen keinen Zugriff.

## Abgrenzung

Skel ist weder ein automatischer CRUD-Generator aus Domain-Modellen noch ein pixelgenauer Zeichenbaum, der im Anwendungscode vollständig nachgebaut werden muss. Es nimmt dem Entwickler nicht die Entscheidung über UI-Inhalt, Aktion, Anordnung oder Verhalten ab. Die View-Komposition ist explizit; Wiederverwendung und lineare Builder-Pipelines sollen sie lesbar halten.

Die Idee der „flachen Komposition“ bedeutet nicht, dass der gerenderte DOM- oder Node-Baum verschwindet. Sie beschreibt die angestrebte Ergonomie beim Schreiben von UI-Code. Auch „servergetrieben“ bedeutet nicht automatisch, dass der Browser gar keinen Zustand besitzt oder jede denkbare Anwendung ohne Clientlogik auskommt.

### Produktumfang und Nicht-Ziele

Skels Produktziel ist, React und Angular **als Frontend-UI-Frameworks** zu ersetzen: Entwickler sollen damit Web-UIs komponieren, darstellen, navigieren und interaktiv machen können. Das bedeutet keine vollständige Funktionsparität mit jedem Ökosystem-Paket oder jeder Integrationsmöglichkeit dieser Frameworks. Bewertet wird Skel an den Anforderungen typischer Webanwendungen und am hier beschriebenen expliziten, servergetriebenen Modell.

Skel soll dafür UI-Primitiven, Rendering, Formulare, Navigation, Assets, Accessibility, optionale Client-Islands sowie passende Entwicklungs- und Testwerkzeuge bereitstellen. Der aktuelle Rust-Server ist der Ausführungspfad für serverseitiges Rendering und Aktionen; er macht Skel nicht zum Ersatz für Datenbanken, fachliche Backend-Systeme, Identitätsanbieter oder allgemeine Server- und Hosting-Plattformen. Anwendungen bleiben für ihre fachlichen Daten und deren Persistenz verantwortlich und können vorhandene Dienste integrieren.

Single-Instance-Betrieb mit flüchtigem UI-Sessionzustand ist das zugrunde gelegte Betriebsmodell. Mehrere Skel-Instanzen, ein verteilter oder persistenter UI-Session-Store, Hochverfügbarkeit und horizontale Skalierung sind keine Anforderungen für das Framework-Ziel. Bei einem Prozessneustart darf flüchtiger UI-Zustand verloren gehen; fachliche Anwendungsdaten müssen unabhängig davon persistiert werden. Proxy-, TLS- und Authentifizierungsintegration müssen für reale Anwendungen sicher dokumentiert und integrierbar sein, sind aber kein Auftrag, Skel zu einem eigenen Edge-, Identity- oder Backend-Produkt auszubauen.

## Zielumfang für Webanwendungen

„Webapp-Standard“ meint hier eine belastbare Grundlage, um typische React- oder Angular-basierte Web-UIs mit Skel umzusetzen — nicht Funktionsgleichheit mit jedem SPA-Framework und keine automatische Konformitätsgarantie. Skel soll Entwicklern bewusst gewählte primitive Bausteine und klare Verträge anbieten:

- **Semantisches HTML und Accessibility:** native Elemente, korrekte Beschriftung und Tastaturbedienung, Fokus- und Fehlerzustände sowie dokumentierte Accessibility-Prüfungen. WCAG 2.2 AA ist ein angestrebtes Abnahmekriterium für Skel-eigene Beispiele und Komponenten; Anwendungsseiten müssen weiterhin geprüft werden.
- **Navigation und HTTP-Verhalten:** explizites Routing, methoden- und statusgerechte Antworten, Redirects, 404-/Fehlerseiten und progressive Navigation, ohne URLs oder Fehler stillschweigend umzudeuten.
- **Formulare und Aktionen:** serverseitige Parsing- und Validierungsgrenzen, typisierte Anwendungsfehler, gezielte Rückmeldung pro Feld und erneute Prüfung von Berechtigungen und Invarianten bei jeder Aktion. Formulare sollen als sichere native POSTs auch ohne JavaScript funktionieren; der optionale Client darf sie progressiv über den Wire-Kanal verbessern.
- **Sicherheitsgrundlagen:** begrenzte Request-/Body-Größen und Laufzeiten, korrektes HTTP-Framing, sicheres HTML-/Attribut-Encoding, belastbares Session- und CSRF-Modell, Origin-/Content-Type-Regeln und dokumentierte Proxy-/TLS-Betriebsgrenzen. Konkrete Defaults und Bedrohungsmodell sind vor Produktivbetrieb festzulegen.
- **Explizite Client-Islands:** benannte Einbindung, begrenzte DOM-/Zustandsverantwortung, definierte Lebensdauer und Fehlerbehandlung, progressive Fallbacks sowie Tests für die Schnittstelle mit serverseitigen Intents. Kein stilles Hydrieren oder automatisches Ableiten interaktiver Controls.
- **Entwicklerwerkzeuge und Integration:** nachvollziehbare Fehlerdiagnosen, lokale Entwicklung mit schnellem Feedback, stabile Asset-Auslieferung, reproduzierbare Builds, Testhilfen und klare Integrations-/Deploy-Anleitungen für den vorgesehenen Single-Instance-Betrieb.
- **Responsive und performante Auslieferung:** mobile Layouts, komprimierbare Assets und messbare Lade- und Interaktionsleistung. Kleine Bundles, ETags oder wenige Dependencies gelten nicht allein als Performance-Nachweis.

Ein Produktionsstatus für diesen Umfang bedeutet, dass Teams die UI-Schicht typischer Anwendungen mit den dokumentierten Skel-Primitiven sicher und zugänglich entwickeln, testen und integrieren können. Er verlangt keine verteilte Serverarchitektur, keinen Ersatz vorhandener Backend-Systeme und keine pauschale Garantie für die Qualität oder Sicherheit der damit gebauten Anwendungen.

### Vorgeschlagene Etappen

1. **Sicherer HTTP-Kern:** Request-Framing und Größenlimits korrekt behandeln, ungültige Eingaben ablehnen, Verbindungen begrenzen und Fehler explizit melden.
2. **Web-Primitiven:** Routing, Statuscodes, Header, Assets und Fehlerbehandlung als explizite APIs ergänzen.
3. **Zugängliche Komponenten und Formulare:** semantische Ausgabe, Beschriftung, Tastatur-/Fokusverhalten sowie Validierung und Fehlerfeedback mit automatisierten und manuellen Prüfungen absichern.
4. **Sitzungen und Aktionen:** Identität, Session-Lebenszyklus, CSRF-Schutz und serverseitige Capability-Prüfungen als nachvollziehbaren End-to-End-Vertrag etablieren.
5. **Client-Island-Vertrag:** erst nach stabiler Serverbasis ein minimales, opt-in Protokoll samt Lifecycle, Fallbacks und Tests definieren.
6. **Referenzanwendung und Messung:** eine typische React-/Angular-Web-UI als begrenzten, realen Anwendungsfall mit Skel umsetzen und Bedienbarkeit, Accessibility, Interaktionslatenz, Build-/Feedback-Zeit und Integrationsaufwand messen.

Diese Reihenfolge ist ein Vorschlag zur Umsetzung, kein Versprechen, dass einzelne Etappen bereits begonnen oder geliefert sind. Eine Migration der gesamten `sb-workbench` ist keine Voraussetzung und bleibt eine separate Entscheidung.

## Stand im Repository

Im früheren Verzeichnis `tools/skel` (vor der Ausgliederung als externes Satelliten-Projekt) existierte ein Rust-Crate-Verbund mit `skel-core`, `skel-builder`, `skel-wire`, `skel-client`, `skel-server`, `skel-macros` und `skel-style`. Der historische Code umfasste unter anderem:

- semantische `Node`- und `SkelView`-Abstraktionen,
- Builder für Views, Formulare, Tabellen und Header,
- explizite, opt-in Client-Islands (`Node::island`, `IslandBuilder`) mit progressivem No-JS-Fallback, typisiertem JSON-Props-Vertrag und browserseitigem Lifecycle (`window.skel.registerIsland(name, factory)`),
- explizite, servergerenderte GET-Routen mit statischen und benannten dynamischen Pfadsegmenten zusätzlich zur Standardseite `/`; nicht registrierte Seitenpfade liefern 404,
- semantische Navigationslinks als reguläre HTML-Anker, die auch ohne JavaScript funktionieren,
- HTML-Rendering, ein JSON-basiertes Intent-/Patch-Protokoll und ETag-basierte Diff-Berechnung,
- einen kleinen eingebetteten Browser-Client und einen Hyper-basierten HTTP/1.x-Server mit 16 Runtime-Threads, höchstens 48 aktiven Verbindungen, fünf Sekunden Header-/Body-Lesefrist, maximal 16 KiB Headern, 100 Headerfeldern und 1 MiB Request-Body; `serve_with_shutdown` bietet einen begrenzten Drain-Pfad,
- `AppContext`-Funktionen für Capabilities sowie die Möglichkeit, Anwendungs-Intents zu registrieren.

Eine Route wird über `SkelApp::route(path, title, renderer)` registriert. `:name` in einem Pfadsegment erfasst einen URL-dekodierten Pfadparameter; `RouteRequest::param`, `query_first` und `query_all` stellen Pfad- und Query-Werte explizit bereit. Statische Pfade haben Vorrang vor dynamischen Segmenten; gleichrangige, überlappende Routen werden bei der Registrierung abgewiesen. Links aus `Node::link(id, label, href)` werden als normale `<a>`-Elemente ausgegeben; unsichere URL-Schemata werden beim Rendern abgelehnt. Der Browser übermittelt den angezeigten Seitenpfad auch bei Wire-Anfragen; der Server validiert ihn und verwendet ihn nur zur Auswahl der Ansicht, niemals als Autorisierungsnachweis. Formulare werden als `POST /_skel/form` mit URL-encoded Feldern und verborgenem Session-CSRF-Token, Seitenpfad, Zielformular, Aktion und ETag ausgegeben. Same-Origin-, Session-, CSRF-, Ziel-, Aktions- und ETag-Prüfungen laufen auch im nativen Formularpfad serverseitig. Feldfehler antworten mit 422 und rendern die übermittelten Werte erneut; Erfolg verwendet 303 See Other (Post/Redirect/Get). Die feste Formular-Metadaten-Namensfamilie `_skel_*` ist reserviert. `FormBuilder::id(...)` setzt eine explizite eindeutige Formular-ID, wenn mehrere Formulare dieselbe Aktion verwenden; Feld-IDs werden innerhalb des Formulars positionsbasiert erzeugt. Generische Anwendungsrouten unterstützen GET und HEAD; andere Methoden außerhalb von `/_skel/` antworten mit 405 und `Allow`. `SkelApp::redirect(from, to, permanent)` registriert 308/307-Weiterleitungen auf same-origin-Pfade (Open-Redirect-Ziele werden abgewiesen). `SkelApp::asset(path, content_type, bytes)` liefert Dateien unter `/assets/…` sessionlos mit ETag/304, `nosniff` und Sandbox-CSP. `GET /_skel/health` liefert `{"status":"ok"}`; jede Anfrage erzeugt eine Access-Log-Zeile (Methode, Pfad ohne Query, Status, ms; abschaltbar mit `access_log(false)`). Die Session-Kapazität ist auf 1024 begrenzt (danach 503) und per Lasttest abgesichert. `FormBuilder::typed_field` erlaubt nur freigegebene Input-Typen; Passwortfelder werden bei 422 nie neu befüllt. Offen bleiben weitere Komponenten und TLS-/Reverse-Proxy-Feinheiten.

Der Laufzeitserver verwendet Hyper für HTTP/1.x-Framing und schließt die Verbindung nach jeder Antwort; Hyper verarbeitet unterstützte `Content-Length`- und Chunked-Requests, während Skel den eingelesenen Body auf 1 MiB begrenzt. Die öffentliche `HttpRequest::read_from`-Hilfsfunktion bleibt ein separater, enger Parser für Content-Length-Requests und ist nicht der Netzwerkserver. Der Einsatz einer etablierten HTTP-Bibliothek reduziert eigenes Parser-Risiko, ist aber keine vollständige Umsetzung dieser Arbeitsdefinition. Insbesondere belegen die aktuellen Tests keine Produktionsreife, vollständige HTTP-/Browser-Sicherheit, universelle serverseitige Autorisierung oder einen Compile-Zeit-Beweis von Berechtigungen. Die bestehende `SkelEntity`-Ableitung berechnet einen ETag; daraus folgt keine automatische UI-Projektion und kein Beweis fachlicher Korrektheit. Auch Stylesheet-Syntax und -Funktionen aus Konzeptbeispielen sind nicht ohne Implementierung als verfügbare Skel-Funktionen anzusehen.

Der optionale `with_context_resolver` muss den `AppContext` für jede Anfrage anhand vertrauenswürdiger Authentifizierungsdaten bestimmen; ohne Resolver wird ein Guest-Kontext verwendet. Der Browsertransport verwendet eine serverseitig gespeicherte, kryptografisch zufällige `HttpOnly`-/`Secure`-/`SameSite=Strict`-Cookie-Session, einen pro Sitzung erzeugten CSRF-Token und eine Same-Origin-Prüfung für Wire-POSTs. Sessions sind auf 30 Minuten Inaktivität begrenzt und an den im Context aufgelösten Subject gebunden. Der frühere `X-Skel-Session`-Header wird nicht mehr akzeptiert. `allow_insecure_cookies_for_local_development` ist ausschließlich für lokale HTTP-Entwicklung vorgesehen; Produktionsdeployments müssen beim sicheren Standard bleiben. Das aktuelle Beispiel gewährt absichtlich statisch Demo-Adminrechte und ist keine Vorlage für Produktionsauthentifizierung. Intent-ETags schützen vor veralteten UI-Zuständen, ersetzen aber weder Authentifizierung noch Autorisierung oder fachliche Validierung.

Für den derzeitigen Serververtrag terminiert ein Reverse-Proxy öffentliches HTTPS; Skel bindet ausschließlich an IPv4-Loopback. Der Proxy muss den eingehenden `Host`-Header unverändert und eindeutig weitergeben; `Forwarded`-/`X-Forwarded-*`-Header werden von Skel nicht als Vertrauensbeweis verwendet. TLS, HSTS, öffentliches Host-Allowlisting, Request-Ratenbegrenzung und Schutz des Proxy-zu-Backend-Pfads müssen durch die Deployment-Konfiguration abgesichert und getestet werden. Die In-Memory-Sessions überstehen keinen Prozessneustart und sind nicht zwischen mehreren Instanzen geteilt; das entspricht dem festgelegten Single-Instance-Ziel, wobei flüchtiger UI-Zustand bei Neustart verloren geht. Die beschriebenen Implementierungs- und Testgrenzen bleiben bestehen; diese Arbeitsdefinition ist weder eine Produktionsfreigabe noch ein Ersatz für eine umfassend geprüfte HTTP- und Deployment-Konfiguration.

### Betriebs-Checkliste (Single-Instance hinter Reverse-Proxy)

- Proxy terminiert TLS, setzt HSTS und leitet `Host` unverändert weiter; Skel bleibt an Loopback gebunden.
- Cookies bleiben `Secure` (`__Host-`-Präfix); die Insecure-Option ist nur für lokale Entwicklung.
- Health-Check des Proxys/Orchestrators: `GET /_skel/health` (ohne Session, 200 `{"status":"ok"}`).
- Lastgrenzen: 1024 Sessions (danach 503), 30 min Idle-Timeout, 1 MiB Body, 5 s Verbindungs-Timeout; Ratenbegrenzung gehört in den Proxy.
- Access-Log geht auf stderr (ohne Query-String); Rotation übernimmt der Prozess-Supervisor.
- Formularfelder: `typed_field` unterstützt `text`, `email`, `password`, `number`, `tel`, `url`, `search`, `date` und `textarea`; dazu `select_field` (Wiederherstellung nur für bekannte Optionen) und `checkbox_field`.
- Weitere Nodes: `Dialog` (nicht-modaler Inline-Dialog mit `role="dialog"`) und `Tabs` (link-basiert, rendert nur das aktive Panel, funktioniert ohne JS).
- Ein Intent-Handler, der `Err` zurückgibt, aber Feldfehler gesetzt hat, gilt als Validierung (422 bzw. Patch), sonst als Fehler (500/`INTENT_FAILED`).
- Browser-Navigationsfehler (`Accept: text/html`, außerhalb `/_skel/`) erhalten eine HTML-Fehlerseite, API-Clients weiter JSON.
- `Referrer-Policy: same-origin` (nicht `no-referrer`), damit Browser bei nativen Formular-POSTs den echten `Origin` für die CSRF-Prüfung senden.
- Browser-E2E: `cargo build -p skel --example audit_viewer`, dann in `tools/skel/e2e` `npm install` und `npm test` (Playwright-Core mit lokalem Chrome/Edge, prüft JS- und No-JS-Pfad, Flash, Pagination und SSE).
- Flash-Meldungen: `ctx.flash(text, FlashKind::{Info,Success,Warning,Error})` überlebt Post/Redirect/Get (sessiongepufferte Queue, begrenzt, wird beim nächsten GET genau einmal gerendert; HEAD verbraucht nichts). Gerendert in `<div id="skel-flash" role="status" aria-live="polite">`; Wire-Intents liefern sie als flüchtigen Patch (leerer `new_etag`, vom Client nicht getrackt).
- DataGrid: `sortable_column(titel, href, SortDirection)` rendert Header-Links mit `aria-sort`, `paginate(aktuell, gesamt, "/pfad?page=")` ein `<nav aria-label="Seitennavigation">` mit `aria-current="page"`. Beides funktioniert ohne JS über Query-Parameter (`RouteRequest::query_first`); der Server sortiert und schneidet die Seite selbst.
- `assets_dir("/assets", "./static")`: rekursiver Scan beim Start (Symlinks/Dotfiles übersprungen, Limits für Tiefe, Dateianzahl und Größe), je Datei Plain-Pfad (Revalidate/304) und Fingerprint-Pfad `name.sbe_<hash>.ext` (`immutable`, ein Jahr). Textformate erhalten beim Start vorberechnete gzip-/Brotli-Varianten (`Accept-Encoding` mit q-Werten, `Vary`). `asset_url("/assets/app.css")` liefert die Fingerprint-URL. HTML wird bewusst nicht ausgeliefert.
- Live-Push (SSE): `SkelApp::live("/pfad")` markiert eine Seite als live (`<meta name="skel-live">`); der Client öffnet `GET /_skel/stream?page=…` und erhält dieselben Patches wie bei einem Sync (`event: patch`), Heartbeat alle 15 s, `event: expired` bei abgelaufener Session. Auslöser: `PushHandle::notify()` (aus `push_handle()`, aus beliebigen Threads) sowie jeder erfolgreiche Intent/Form-Post. Same-Origin-/Cookie-/Session-Prüfung wie bei Wire; höchstens 24 gleichzeitige Streams. Grenzen: Seitenübergreifende Live-Updates setzen geteilten Zustand voraus (z. B. `Arc<Mutex<…>>` im View, siehe `examples/audit_viewer.rs`); die Session wird durch den Stream nicht verlängert; beim Shutdown wartet der Server bis zu 10 s auf offene Streams; eigene Intents erzeugen zusätzlich einen redundanten, idempotenten Stream-Patch.
- Dogfooding: `tools/skel/examples/audit_viewer.rs` setzt den `AuditViewer` aus `tools/sb-desktop` als Skel-App um (SSH-Sessions aus `~/.sb/audit/sessions.jsonl` mit Demo-Fallback, Sortierung, Pagination, Flash, SSE bei Dateiänderung, `assets_dir`); Port 7072.
- ETags sind Änderungs-Token für Reaktivität, keine Sicherheitsgrenze: Der Server versiegelt jeden deklarierten ETag automatisch mit dem Inhalt des Teilbaums (`Node::seal_etags`, BLAKE3, 64 Bit). Ein handgesetzter ETag wirkt nur noch als Salz; ändert sich der Inhalt, ändert sich der ETag (auch bei Vorfahren), sodass kein Patch verloren geht. Tests lesen den aktuellen ETag per `sync()` aus, statt Konstanten zu erwarten.
- Typeahead: Ein `InputField` mit `.attr("skel-debounce", "200ms")` innerhalb eines `form[skel-action]` sendet das Formular nach der Inaktivität als Intent (Wert 50 ms bis 5 s, sonst ignoriert), ohne eigenes JS.
- Testharness ohne Browser und Netzwerk: `SkelTestSession::from_app(app)` (bzw. `with_app(titel, view, |app| …)`) fährt die echte Request-Pipeline im Speicher (Cookie, CSRF, Origin, ETag- und Aktionsprüfung bleiben aktiv). `visit(pfad)`, `follow(&res)`, `dispatch(aktion, json!({…}))` (Ziel und ETag werden aus der Live-View ermittelt), `submit_form(aktion, &[(feld, wert)])` und `sync()`; `TestResponse` bietet `status()`, `location()`, `error_code()`, `contains()` und `patches().contains_target(id)`.
- Single-Binary: `embed_assets("/assets", &[("/app.css", include_bytes!("../static/app.css"))])` nutzt dieselbe Pipeline wie `assets_dir` (Fingerprint, MIME, gzip/Brotli, immutable) ohne Dateien zur Laufzeit; Pfade werden streng validiert (`[A-Za-z0-9._-]`, keine Dotfiles). Es gibt bewusst kein `include_dir!`-Makro (keine zusätzliche Abhängigkeit).
- Deklaratives Makro `skel! { <div class="x"><Metric label="CPU" value="4" unit="%" /><Button action="rescan">"Aktualisieren"</Button></div> }` (Compile-Time, null Runtime-Overhead; funktioniert in Crates mit `skel`-Abhängigkeit). Kinder: `"Text"`, `{expr}`, `{..iter}`, `if`/`else`, `for x in expr { }`. Komponenten: `Container`, `Header`, `Text`, `Metric`, `Button`, `Badge`, `Link`, `Input`; kleingeschriebene Tags nur aus der Renderer-Whitelist, `on*`-Attribute sind ein Compile-Fehler. IDs: `id="…"` explizit, sonst automatisch `eltern-index`; zustandsbehaftete Nodes (Forms, Inputs) sollten explizite IDs haben, weil sich positionale IDs bei Geschwisteränderungen verschieben. Dieselben Bausteine gibt es als Funktionen in `skel_builder::ui` (`div`, `metric`, `button`, …) sowie `Node::children`/`child_if`.
- Out-of-Band-Patches: Der Client sendet bei Intents seine bekannten ETags mit (`known_etags`). Die Antwort enthält jede Komponente der Seite, deren ETag sich geändert hat (z. B. Tabelle und Header-Badge), nicht nur das Ziel; Flash kommt weiterhin als transienter `skel-flash`-Patch. Die Map ist serverseitig begrenzt (4096 Einträge, 256 Zeichen je Schlüssel/Wert).
- `.watch()`: `app.watch(watch_receiver, |wert| { /* geteilten Zustand mutieren */ })` bzw. `app.watch_broadcast(broadcast_receiver, …)` startet beim Serve einen Task, der nach jedem Wert den Closure aufruft und danach `PushHandle::notify()` auslöst (SSE-Diff nur für geänderte ETags). Gedacht für geteilten Zustand (`Arc<Mutex<…>>`), nicht für Session-Zustand.
- View Transitions: Der Client wrappt DOM-Patches automatisch in `document.startViewTransition` (mit Fallback).
- SPA-Routing: Klicks auf Same-Origin-Links (nicht `/_skel/`, kein `target`/`download`, keine Modifier-Tasten, Opt-out mit `skel-reload`) laden die Zielseite per `fetch`, morphen sie in einer View Transition ein und pflegen Titel, History (`pushState`/`popstate`), ETags, CSRF-Token und SSE-Stream; es gibt kein Neuladen und kein schwarzes Flackern. Nicht-HTML, Fehlerstatus, fremde Origin oder Netzfehler fallen auf normale Navigation zurück. `@view-transition { navigation: auto }` glättet zusätzlich harte Navigationen (z. B. PRG nach Formular-POST). Ohne JavaScript funktionieren alle Links unverändert.

## Workbench-Bezug

`sb-workbench` könnte später als anspruchsvolle Referenzanwendung und Dogfooding-Ziel für Skel dienen. Die vollständige Migration der bestehenden Tauri-/React-Workbench ist durch diese Definition nicht beschlossen. Vor einer solchen Entscheidung müssen Integrationsgrenzen, Laufzeitmodell, Browser- und Tauri-Unterstützung, Live-Updates, Barrierefreiheit, Sicherheit sowie ein realistischer Build-, Test- und Ressourcenvergleich geklärt werden. Leistungs- oder Speicherersparnisse werden erst nach einem reproduzierbaren Vergleich behauptet.
