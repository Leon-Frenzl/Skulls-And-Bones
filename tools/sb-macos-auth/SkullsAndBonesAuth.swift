// Skulls & Bones macOS Authorization Plugin ("Bei Skulls & Bones anmelden")
// Build as a macOS bundle (`SkullsAndBonesAuth.bundle`) and install into
// `/Library/Security/SecurityAgentPlugins/SkullsAndBonesAuth.bundle`.

import Foundation
import SecurityInterface
import AppKit

@objc(SBAuthPluginView)
public final class SBAuthPluginView: SFAuthorizationPluginView {
    private let usernameField = NSTextField(frame: NSRect(x: 0, y: 42, width: 260, height: 26))
    private let passwordField = NSSecureTextField(frame: NSRect(x: 0, y: 10, width: 260, height: 26))
    private let container = NSView(frame: NSRect(x: 0, y: 0, width: 280, height: 96))

    public override init!(callbacks: UnsafePointer<AuthorizationCallbacks>!, andEngineRef engineRef: AuthorizationEngineRef!) {
        super.init(callbacks: callbacks, andEngineRef: engineRef)
        let label = NSTextField(labelWithString: "Bei Skulls & Bones anmelden")
        label.frame = NSRect(x: 0, y: 72, width: 260, height: 20)
        label.font = NSFont.boldSystemFont(ofSize: 13)
        usernameField.placeholderString = "Domänen-Benutzer (z. B. leon.admin)"
        passwordField.placeholderString = "Passwort"
        container.addSubview(label)
        container.addSubview(usernameField)
        container.addSubview(passwordField)
    }

    public override func view(for type: SFViewType) -> NSView! {
        return container
    }

    public override func buttonPressed(_ inButtonType: SFButtonType) {
        if inButtonType == .OK {
            let user = usernameField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
            let pass = passwordField.stringValue
            if verifyWithLocalBroker(username: user, password: pass) {
                setEnabled(true)
            }
        }
        super.buttonPressed(inButtonType)
    }

    private func verifyWithLocalBroker(username: String, password: String) -> Bool {
        // Connects to `/run/sb-node/auth.sock` and sends JSON `{ "username": ..., "password": ... }\n`.
        guard let payload = try? JSONSerialization.data(withJSONObject: ["username": username, "password": password]) else {
            return false
        }
        var line = payload
        line.append(0x0A)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let sockPath = "/run/sb-node/auth.sock"
        _ = sockPath.withCString { cstr in
            withUnsafeMutablePointer(to: &addr.sun_path.0) { ptr in
                strcpy(ptr, cstr)
            }
        }
        let len = socklen_t(MemoryLayout<sockaddr_un>.size)
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, len) }
        }
        guard rc == 0 else { return false }
        _ = line.withUnsafeBytes { write(fd, $0.baseAddress, line.count) }
        var buf = [UInt8](repeating: 0, count: 1024)
        let n = read(fd, &buf, buf.count)
        guard n > 0, let resp = try? JSONSerialization.jsonObject(with: Data(buf[0..<n])) as? [String: Any] else {
            return false
        }
        return (resp["allowed"] as? Bool) == true
    }
}
