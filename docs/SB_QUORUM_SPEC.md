# `sb-quorum`: aktueller Umfang und Sicherheitsstatus

## Umfang

`sb-quorum` ist derzeit eine lokale CLI-Funktion in `sb`. Die unterstützten Proposal-Kategorien sind:

- `CodeMerge`
- `SecretUnlock`
- `InfraConfig`
- `FleetDestruct`
- `Generic`

Quorum-Proposals liegen lokal in `~/.sb/quorum/proposals.json`. Shadow-PC-, Remote-Bildschirm- und Eingabefreigaben sind kein unterstützter Anwendungsfall. Die CLI weist neue Shadow-Zugriffskategorien zurück. Bereits gespeicherte JSON-Proposals mit der Kategorie `ShadowAccess` bleiben lesbar und werden als `Generic` behandelt; daraus wird keine Shadow-PC-Aktion ausgelöst.

## Sicherheitsgrenze

Der aktuelle lokale Proposal-Workflow ist ein Prototyp, keine produktive Autorisierungs- oder kryptographische Quorum-Grenze. Insbesondere belegt der aktuelle Code weder echte Ed25519-Signaturprüfung noch verteiltes Proposal-Gossip, eine serverseitige Durchsetzung der genehmigten Aktion oder einen sicheren Multi-Writer-Speicher.

Mesh-Services dürfen daher eine Proposal-Anzeige oder einen `Approved`-Status nicht als Berechtigung behandeln. Jede produktive Operation muss ihre aktuelle Identität, Mitgliedschaft, Capability, Ressourcen-ACL, Ablauf- und Widerrufsregeln am autoritativen Dienst selbst prüfen.

## Voraussetzungen für eine spätere Produktionsfreigabe

Vor produktiver Nutzung sind mindestens erforderlich:

1. kanonische, domain-separierte Signaturen über Proposal-Identität, Aktion, Zielressource, Mesh, Policy-Epoch und Ablauf;
2. Verifikation der Signaturen und Unabhängigkeit der Reviewer am autoritativen Dienst;
3. atomare, crash-konsistente Speicherung sowie Replay-, Ablauf- und Widerrufsbehandlung;
4. Negativtests für manipulierte Proposals, ungültige Signaturen, doppelte Reviewer, veraltete Policies und abgelehnte Ressourcen-ACLs;
5. ein expliziter Transport- und Synchronisationsvertrag, falls Proposals zwischen Peers geteilt werden.

Bis diese Gates erfüllt sind, darf `sb-quorum` nicht als Ersatz für Service-Autorisierung verwendet werden.
