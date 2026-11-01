use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Galois Field GF(2^8) mit Rijndael-Polynom 0x11B (x^8 + x^4 + x^3 + x + 1).
/// Exakte Byte-Level Arithmetik für Shamir's Secret Sharing und PSS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf256;

impl Gf256 {
    pub const POLY: u16 = 0x11B;

    #[inline]
    pub fn add(a: u8, b: u8) -> u8 {
        a ^ b
    }

    #[inline]
    pub fn sub(a: u8, b: u8) -> u8 {
        a ^ b
    }

    pub fn mul(mut a: u8, mut b: u8) -> u8 {
        let mut p: u8 = 0;
        for _ in 0..8 {
            if (b & 1) != 0 {
                p ^= a;
            }
            let carry = (a & 0x80) != 0;
            a <<= 1;
            if carry {
                a ^= (Self::POLY & 0xFF) as u8;
            }
            b >>= 1;
        }
        p
    }

    pub fn inv(a: u8) -> u8 {
        if a == 0 {
            return 0;
        }
        // Fermats kleiner Satz in GF(2^8): a^(254) = a^(-1)
        let mut res: u8 = 1;
        let mut base = a;
        let mut exp: u8 = 254;
        while exp > 0 {
            if (exp & 1) != 0 {
                res = Self::mul(res, base);
            }
            base = Self::mul(base, base);
            exp >>= 1;
        }
        res
    }

    #[inline]
    pub fn div(a: u8, b: u8) -> Result<u8, String> {
        if b == 0 {
            return Err("Division durch Null in GF(256)".to_string());
        }
        Ok(Self::mul(a, Self::inv(b)))
    }
}

/// Repräsentiert einen dezentralen Secret-Shard im Sovereign Swarm
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretShard {
    pub secret_name: String,
    pub shard_id: u8,       // x-Koordinate (1 .. n)
    pub epoch: u32,         // Resharing-Epoche (startet bei 1, inkrementiert bei Revocation)
    pub threshold: u8,      // k
    pub total_shards: u8,   // n
    pub share_data: String, // Base64-kodierte Shamir-Share-Bytes
    pub aont_tag: String,   // Hex-kodierter SHA-256 Checksum der Ciphertext-Blöcke
    pub nonce: String,      // Base64-kodierte 12-Byte Nonce
    pub ciphertext: String, // Base64-kodierter AES-256-GCM Ciphertext
    pub created_at: DateTime<Utc>,
}

/// Evaluierung eines Polynoms an der Stelle x im GF(256)
/// coeffs: [c_0, c_1, c_2, ... c_{k-1}] entspricht c_0 + c_1*x + c_2*x^2 + ...
fn eval_poly(coeffs: &[u8], x: u8) -> u8 {
    let mut result = 0u8;
    let mut x_pow = 1u8; // x^0 = 1
    for &c in coeffs {
        let term = Gf256::mul(c, x_pow);
        result = Gf256::add(result, term);
        x_pow = Gf256::mul(x_pow, x);
    }
    result
}

/// Shamir Secret Sharing: Teilt ein Byte-Array `secret` in `total` (n) Shards mit Schwelle `threshold` (k).
pub fn split_secret_shamir(
    secret: &[u8],
    threshold: usize,
    total: usize,
) -> Result<Vec<(u8, Vec<u8>)>, String> {
    if threshold < 2 {
        return Err("Threshold k muss mindestens 2 sein".to_string());
    }
    if total < threshold {
        return Err("Total n muss >= threshold k sein".to_string());
    }
    if total > 255 {
        return Err("Maximal 255 Shards in GF(256) unterstützt".to_string());
    }

    let mut shares: Vec<(u8, Vec<u8>)> = (1..=total)
        .map(|i| (i as u8, Vec::with_capacity(secret.len())))
        .collect();

    let mut rng = OsRng;

    // Byte-weise Shamir-Polynome generieren
    for &byte in secret {
        let mut poly = Vec::with_capacity(threshold);
        poly.push(byte); // f(0) = byte
        for _ in 1..threshold {
            let mut rand_coeff = [0u8; 1];
            loop {
                rng.fill_bytes(&mut rand_coeff);
                if rand_coeff[0] != 0 {
                    break;
                }
            }
            poly.push(rand_coeff[0]);
        }

        // Shard-Bytes an Positionen x_i = 1..total berechnen
        for (x, buf) in &mut shares {
            let y = eval_poly(&poly, *x);
            buf.push(y);
        }
    }

    Ok(shares)
}

/// Lagrange-Interpolation: Rekonstruiert das Secret aus mindestens k Shares.
pub fn combine_shares_shamir(
    shares: &[(u8, Vec<u8>)],
    threshold: usize,
) -> Result<Vec<u8>, String> {
    if shares.len() < threshold {
        return Err(format!(
            "Unzureichende Shard-Anzahl: {} vorhanden, aber Schwelle ist {}",
            shares.len(),
            threshold
        ));
    }

    // Nimm genau die ersten k Shares
    let k_shares = &shares[..threshold];
    let len = k_shares[0].1.len();
    for (x, s) in k_shares {
        if s.len() != len {
            return Err("Shard-Daten haben inkonsistente Längen".to_string());
        }
        if *x == 0 {
            return Err("Ungültiger Shard-Index 0".to_string());
        }
    }

    // Prüfe auf Duplikate bei den x-Werten
    let mut seen_x = HashSet::new();
    for (x, _) in k_shares {
        if !seen_x.insert(*x) {
            return Err(format!("Doppelter Shard-Index {} entdeckt", x));
        }
    }

    let mut secret = Vec::with_capacity(len);

    // Byte-für-Byte Lagrange-Interpolation an x = 0
    for byte_idx in 0..len {
        let mut byte_val = 0u8;

        for (i, (x_i, y_i)) in k_shares.iter().enumerate() {
            // Berechne Lagrange-Basisfunktion L_i(0) = \prod_{j != i} (x_j / (x_i ^ x_j))
            let mut l_i = 1u8;
            for (j, (x_j, _)) in k_shares.iter().enumerate() {
                if i != j {
                    let num = *x_j;
                    let den = Gf256::sub(*x_i, *x_j); // Im GF(256): x_i ^ x_j
                    let frac = Gf256::div(num, den)?;
                    l_i = Gf256::mul(l_i, frac);
                }
            }

            let term = Gf256::mul(y_i[byte_idx], l_i);
            byte_val = Gf256::add(byte_val, term);
        }

        secret.push(byte_val);
    }

    Ok(secret)
}

/// AONT-Pipeline: Verschlüsselt `payload` mit AES-256-GCM, verwebt den Key mit dem Ciphertext-Hash (AONT)
/// und teilt den maskierten Key mittels Shamir in n Shards mit Threshold k.
pub fn generate_aont_shards(
    secret_name: &str,
    payload: &[u8],
    threshold: usize,
    total: usize,
) -> Result<Vec<SecretShard>, String> {
    // 1. Ephemeren AES-256-Key und Nonce erzeugen
    let mut eph_key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut eph_key_bytes);

    let key = Key::<Aes256Gcm>::from_slice(&eph_key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // 2. Payload symmetrisch verschlüsseln
    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|e| format!("AES-GCM Verschlüsselungsfehler: {}", e))?;

    // 3. AONT Canary Hash über Ciphertext bilden: H = SHA-256(ciphertext)
    let mut hasher = Sha256::new();
    hasher.update(&ciphertext);
    let aont_hash: [u8; 32] = hasher.finalize().into();

    // 4. Key maskieren: K' = K_eph ^ H(ciphertext)
    let mut masked_key = [0u8; 32];
    for i in 0..32 {
        masked_key[i] = eph_key_bytes[i] ^ aont_hash[i];
    }

    // 5. Maskierten Key K' in n Shamir-Shards zerlegen
    let shares = split_secret_shamir(&masked_key, threshold, total)?;

    let now = Utc::now();
    let aont_tag = hex::encode(aont_hash);
    let b64_nonce = BASE64.encode(&nonce);
    let b64_ciphertext = BASE64.encode(&ciphertext);

    let mut result = Vec::with_capacity(total);
    for (shard_id, share_data) in shares {
        result.push(SecretShard {
            secret_name: secret_name.to_string(),
            shard_id,
            epoch: 1,
            threshold: threshold as u8,
            total_shards: total as u8,
            share_data: BASE64.encode(&share_data),
            aont_tag: aont_tag.clone(),
            nonce: b64_nonce.clone(),
            ciphertext: b64_ciphertext.clone(),
            created_at: now,
        });
    }

    Ok(result)
}

/// AONT-Rekonstruktion: Kombiniert >= k Shards, extrahiert K', rekonstruiert K_eph und entschlüsselt den Payload.
pub fn reconstruct_aont_secret(shards: &[SecretShard]) -> Result<Vec<u8>, String> {
    if shards.is_empty() {
        return Err("Keine Shards übergeben".to_string());
    }

    let first = &shards[0];
    let threshold = first.threshold as usize;
    let epoch = first.epoch;

    if shards.len() < threshold {
        return Err(format!(
            "Unzureichende Shard-Anzahl: {} vorhanden, mindestens {} benötigt",
            shards.len(),
            threshold
        ));
    }

    // Konsistenzprüfung: Alle Shards müssen zur selben Epoche, Secret-Name und zum selben Ciphertext gehören
    for (idx, s) in shards.iter().enumerate() {
        if s.epoch != epoch {
            return Err(format!(
                "Epochen-Inkonsistenz bei Shard {}: erwartet Epoche {}, gefunden {}",
                s.shard_id, epoch, s.epoch
            ));
        }
        if s.secret_name != first.secret_name {
            return Err(format!(
                "Secret-Name Diskrepanz bei Shard {}: '{}' != '{}'",
                s.shard_id, s.secret_name, first.secret_name
            ));
        }
        if s.aont_tag != first.aont_tag
            || s.ciphertext != first.ciphertext
            || s.nonce != first.nonce
        {
            return Err(format!(
                "Inkonsistente Ciphertext- oder Nonce-Metadaten in Shard {}",
                idx + 1
            ));
        }
    }

    // Shamir-Shares dekodieren
    let mut raw_shares = Vec::with_capacity(shards.len());
    for s in shards {
        let bytes = BASE64
            .decode(&s.share_data)
            .map_err(|e| format!("Base64-Fehler in Shard {}: {}", s.shard_id, e))?;
        raw_shares.push((s.shard_id, bytes));
    }

    // 1. Maskierten Key K' via Lagrange-Interpolation rekonstruieren
    let masked_key = combine_shares_shamir(&raw_shares, threshold)?;
    if masked_key.len() != 32 {
        return Err("Ungültige Schlüssel-Länge nach Rekonstruktion".to_string());
    }

    // 2. Ciphertext und Nonce dekodieren
    let ciphertext = BASE64
        .decode(&first.ciphertext)
        .map_err(|e| format!("Base64-Fehler beim Ciphertext: {}", e))?;
    let nonce_bytes = BASE64
        .decode(&first.nonce)
        .map_err(|e| format!("Base64-Fehler bei der Nonce: {}", e))?;

    // 3. AONT Checksum über Ciphertext berechnen und mit aont_tag verifizieren
    let mut hasher = Sha256::new();
    hasher.update(&ciphertext);
    let calculated_hash: [u8; 32] = hasher.finalize().into();

    if hex::encode(calculated_hash) != first.aont_tag {
        return Err(
            "AONT-Canary-Integritätsprüfung fehlgeschlagen! Der Ciphertext wurde manipuliert."
                .to_string(),
        );
    }

    // 4. Ephemeren Key K_eph demaskieren: K_eph = K' ^ H(ciphertext)
    let mut eph_key = [0u8; 32];
    for i in 0..32 {
        eph_key[i] = masked_key[i] ^ calculated_hash[i];
    }

    // 5. AES-256-GCM Entschlüsselung
    let key = Key::<Aes256Gcm>::from_slice(&eph_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| {
        "Entschlüsselung fehlgeschlagen: Shards ungültig oder Schwellwert verletzt!".to_string()
    })?;

    Ok(plaintext)
}

/// Proactive Secret Sharing (PSS):
/// Rotiert das Polynom dezentral mittels Null-Polynomen (g(0) = 0).
/// Schließt den Shard mit `revoke_shard_id` aus und erzeugt eine frische Epoche (epoch + 1),
/// ohne dass das Secret jemals im Klartext im Speicher rekonstruiert werden muss!
pub fn proactive_reshare(
    active_shards: &[SecretShard],
    revoke_shard_id: u8,
) -> Result<Vec<SecretShard>, String> {
    if active_shards.is_empty() {
        return Err("Keine aktiven Shards übergeben".to_string());
    }

    let first = &active_shards[0];
    let threshold = first.threshold as usize;
    let old_epoch = first.epoch;

    // Filter den zu entfernenden Shard aus
    let remaining_shards: Vec<&SecretShard> = active_shards
        .iter()
        .filter(|s| s.shard_id != revoke_shard_id)
        .collect();

    if remaining_shards.len() < threshold {
        return Err(format!(
            "Nach Revocation verbleiben nur {} Shards. Mindestens {} für Threshold benötigt.",
            remaining_shards.len(),
            threshold
        ));
    }

    let share_len = BASE64
        .decode(&first.share_data)
        .map_err(|e| format!("Base64-Fehler: {}", e))?
        .len();

    let mut rng = OsRng;

    // Für jedes Byte der Shares generieren wir ein Null-Polynom g(x) vom Grad threshold - 1:
    // g(x) = 0 + b_1*x + b_2*x^2 + ... + b_{k-1}*x^{k-1}  =>  g(0) = 0!
    // Dadurch gilt für das neue Polynom h(x) = f(x) + g(x): h(0) = f(0) + 0 = f(0) = Secret!
    let mut zero_polys: Vec<Vec<u8>> = Vec::with_capacity(share_len);
    for _ in 0..share_len {
        let mut poly = Vec::with_capacity(threshold);
        poly.push(0u8); // g(0) = 0 (Null-Polynom)
        for _ in 1..threshold {
            let mut rand_coeff = [0u8; 1];
            loop {
                rng.fill_bytes(&mut rand_coeff);
                if rand_coeff[0] != 0 {
                    break;
                }
            }
            poly.push(rand_coeff[0]);
        }
        zero_polys.push(poly);
    }

    let new_epoch = old_epoch + 1;
    let new_total = remaining_shards.len() as u8;
    let now = Utc::now();

    let mut new_shards = Vec::with_capacity(remaining_shards.len());

    for s in remaining_shards {
        let old_share_bytes = BASE64
            .decode(&s.share_data)
            .map_err(|e| format!("Base64-Fehler in Shard {}: {}", s.shard_id, e))?;

        let mut updated_share_bytes = Vec::with_capacity(share_len);
        for byte_idx in 0..share_len {
            let delta = eval_poly(&zero_polys[byte_idx], s.shard_id);
            let new_byte = Gf256::add(old_share_bytes[byte_idx], delta);
            updated_share_bytes.push(new_byte);
        }

        new_shards.push(SecretShard {
            secret_name: s.secret_name.clone(),
            shard_id: s.shard_id,
            epoch: new_epoch,
            threshold: s.threshold,
            total_shards: new_total,
            share_data: BASE64.encode(&updated_share_bytes),
            aont_tag: s.aont_tag.clone(),
            nonce: s.nonce.clone(),
            ciphertext: s.ciphertext.clone(),
            created_at: now,
        });
    }

    Ok(new_shards)
}

/// Speichert Shards im Zielverzeichnis als JSON-Dateien
pub fn save_shards_to_dir(shards: &[SecretShard], dir: &Path) -> Result<Vec<PathBuf>, String> {
    std::fs::create_dir_all(dir)
        .map_err(|e| format!("Verzeichnis konnte nicht erstellt werden: {}", e))?;

    let mut paths = Vec::new();
    for s in shards {
        let filename = format!(
            "{}.shard-{}.epoch-{}.json",
            s.secret_name, s.shard_id, s.epoch
        );
        let path = dir.join(filename);
        let json = serde_json::to_string_pretty(s)
            .map_err(|e| format!("Serialisierungsfehler für Shard {}: {}", s.shard_id, e))?;
        std::fs::write(&path, json)
            .map_err(|e| format!("Konnte Shard-Datei {:?} nicht schreiben: {}", path, e))?;
        paths.push(path);
    }
    Ok(paths)
}

/// Lädt Shards aus angegebenen Pfaden
pub fn load_shards_from_files(paths: &[PathBuf]) -> Result<Vec<SecretShard>, String> {
    let mut shards = Vec::new();
    for p in paths {
        let content = std::fs::read_to_string(p)
            .map_err(|e| format!("Konnte Shard {:?} nicht lesen: {}", p, e))?;
        let shard: SecretShard = serde_json::from_str(&content)
            .map_err(|e| format!("Ungültiges Shard-Format in {:?}: {}", p, e))?;
        shards.push(shard);
    }
    Ok(shards)
}

// Hex-Helper Funktion ohne externe Abhängigkeit
mod hex {
    pub fn encode<T: AsRef<[u8]>>(data: T) -> String {
        data.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf256_basic_arithmetic() {
        assert_eq!(Gf256::add(0x57, 0x83), 0x57 ^ 0x83);
        assert_eq!(Gf256::sub(0x57, 0x83), 0x57 ^ 0x83);

        // Multiplikationstest mit Rijndael Test-Vektoren
        // 0x53 * 0xCA = 0x01 in GF(2^8) mit POLY 0x11B
        let inv_53 = Gf256::inv(0x53);
        assert_eq!(Gf256::mul(0x53, inv_53), 1);

        for x in 1..=255u8 {
            let inv = Gf256::inv(x);
            assert_eq!(Gf256::mul(x, inv), 1, "Inverses von {} schlug fehl", x);
        }
    }

    #[test]
    fn test_shamir_split_and_combine_exact_threshold() {
        let secret = b"TOP_SECRET_AIR_GAP_SBM_KEY_2026";
        let k = 3;
        let n = 5;

        let shares = split_secret_shamir(secret, k, n).expect("Split succeeds");
        assert_eq!(shares.len(), 5);

        // Beliebige 3 aus 5 müssen exakt rekonstruieren
        let subset_3 = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let recovered = combine_shares_shamir(&subset_3, k).expect("Combine succeeds");
        assert_eq!(recovered, secret);

        // Eine andere 3er-Kombination
        let subset_other = vec![shares[1].clone(), shares[3].clone(), shares[4].clone()];
        let recovered2 = combine_shares_shamir(&subset_other, k).expect("Combine succeeds");
        assert_eq!(recovered2, secret);

        // 2 aus 5 dürfen NICHT den Schlüssel rekonstruieren
        let subset_2 = vec![shares[0].clone(), shares[1].clone()];
        assert!(combine_shares_shamir(&subset_2, k).is_err());
    }

    #[test]
    fn test_aont_secret_sharding_lifecycle() {
        let secret =
            b"postgresql://postgres:ZeroTrustMasterPassword2026@hostinger-prod.sbm:5432/app";
        let k = 3;
        let n = 5;

        // 1. Shards generieren
        let shards =
            generate_aont_shards("db-prod-creds", secret, k, n).expect("AONT Sharding succeeds");
        assert_eq!(shards.len(), 5);

        // 2. Rekonstruktion mit genau 3 Shards
        let subset_3 = vec![shards[0].clone(), shards[1].clone(), shards[3].clone()];
        let decrypted = reconstruct_aont_secret(&subset_3).expect("Decryption succeeds");
        assert_eq!(decrypted, secret);

        // 3. Rekonstruktion mit nur 2 Shards muss scheitern
        let subset_2 = vec![shards[0].clone(), shards[2].clone()];
        let failed_recon = reconstruct_aont_secret(&subset_2);
        assert!(failed_recon.is_err());
    }

    #[test]
    fn test_proactive_resharing_revocation() {
        let secret = b"CLUSTER_ROOT_SIGNING_PASSPHRASE_4096";
        let k = 3;
        let n = 5;

        // 1. Epoch 1: 5 Shards
        let shards_e1 = generate_aont_shards("root-ca", secret, k, n).unwrap();

        // 2. Node mit Shard 3 wird kompromittiert / entlassen -> Revocation!
        let revoked_shard_3 = shards_e1[2].clone(); // Shard ID 3
        assert_eq!(revoked_shard_3.shard_id, 3);

        // 3. Proactive Reshare über verbleibende 4 Shards mittels Null-Polynomen g(0) = 0
        let shards_e2 = proactive_reshare(&shards_e1, 3).expect("Reshare succeeds");
        assert_eq!(shards_e2.len(), 4);
        for s in &shards_e2 {
            assert_eq!(s.epoch, 2);
            assert_ne!(s.shard_id, 3); // Shard 3 ist ausgeschlossen
        }

        // 4. Die neuen Shards der Epoche 2 rekonstruieren das unveränderte Secret
        let subset_e2 = vec![
            shards_e2[0].clone(),
            shards_e2[1].clone(),
            shards_e2[2].clone(),
        ];
        let decrypted_e2 =
            reconstruct_aont_secret(&subset_e2).expect("Epoch 2 decrypts successfully");
        assert_eq!(decrypted_e2, secret);

        // 5. CRITICAL SECURITY CHECK:
        // Ein Angreifer besitzt den alten Shard 3 aus Epoche 1 und stiehlt 2 neue Shards aus Epoche 2
        // Da Shard 3 auf Polynom f(x) liegt, die neuen aber auf h(x) = f(x) + g(x),
        // muss die Rekonstruktion wegen Epochen-Inkonsistenz und falschem Lagrange-Wert scheitern!
        let mut mixed_attack = vec![shards_e2[0].clone(), shards_e2[1].clone(), revoked_shard_3];
        assert!(reconstruct_aont_secret(&mixed_attack).is_err());

        // Selbst wenn der Angreifer die Epochennummer in den Metadaten fälscht:
        mixed_attack[2].epoch = 2;
        let forged_res = reconstruct_aont_secret(&mixed_attack);
        // Entschlüsselung muss wegen AES-GCM Auth-Tag oder AONT fehlschlagen!
        assert!(forged_res.is_err());
    }
}
