# Formal Standards Compliance (IEEE / ISO / RFC)
(Copied from C:\Users\leonf\.gemini\config\skills\standards-compliance\SKILL.md)

This skill enables the agent to check for official, recognized technical standards governing a problem domain, evaluate whether compliance is beneficial, and incorporate the standard into the code and specifications.

## 1. Domain Standards Radar
Relevant standards to reference:
- IETF RFC 4251 (SSH Protocol Architecture - wire format, public key encoding)
- OpenSSH PROTOCOL.certkeys (OpenSSH Certificate Format)
- IETF RFC 5280 (Internet X.509 Public Key Infrastructure Certificate and CRL Profile)
- IETF RFC 8446 (TLS 1.3 Protocol)
- ISO 8601 (Timestamps)

## 2. Pragmatic Adoption Check
- Interoperability: standard wire format and certificate encoding ensures external tools (ssh, ssh-keygen, curl, openssl, browsers) work seamlessly.
- Precision & Edge Cases: clock drift backdating (-60s), serial numbers, valid lifetime limits (max 8h for short-lived certs).

## 3. Code Integration Protocol
1. Cite standard in doc comments.
2. Standard terminology (nonce, serial, valid_after, valid_before, principals, critical_options, extensions, SAN, EKU).
3. Test roundtrip compliance.
