use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use sb_mesh::crypto::{
    decrypt_payload, derive_session_keys, encrypt_payload, pack_message_v2, unpack_header_v2,
    PacketType,
};
use sb_mesh::identity::NodeIdentity;
use sb_mesh::stream::{StealthIngressBridge, StealthStreamClient, StreamFrame};

#[tokio::test]
async fn test_stealth_ingress_ssh_bridge_e2e() {
    // 1. Start a local mock SSH service on 127.0.0.1 (e.g. random port)
    let ssh_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ssh_port = ssh_listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = ssh_listener.accept().await {
            tokio::spawn(async move {
                // Send SSH banner
                stream
                    .write_all(b"SSH-2.0-OpenSSH_9.6p1 S&B Stealth\r\n")
                    .await
                    .unwrap();
                let mut buf = [0u8; 256];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    // Echo back
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    // 2. Setup Identities
    let server_identity = Arc::new(NodeIdentity::generate());
    let client_identity = Arc::new(NodeIdentity::generate());

    let swarm_topic = "sbm-swarm-default";
    let swarm_tag = sb_mesh::crypto::derive_swarm_tag(swarm_topic);

    // 3. Start Server UDP Socket & StealthIngressBridge
    let server_udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server_udp.local_addr().unwrap();

    let bridge = Arc::new(StealthIngressBridge::new(vec![ssh_port]));
    let s_ident = server_identity.clone();
    let s_udp = server_udp.clone();
    let s_tag = swarm_tag;

    tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        let counter = Arc::new(AtomicU64::new(10));
        loop {
            match s_udp.recv_from(&mut buf).await {
                Ok((len, sender_addr)) => {
                    if let Ok((ptype, _tag, sender_pubkey_bytes, counter_in, payload)) =
                        unpack_header_v2(&buf[..len])
                    {
                        if ptype == PacketType::Data && _tag == s_tag {
                            let remote_pub = x25519_dalek::PublicKey::from(sender_pubkey_bytes);
                            let Ok(session_keys) =
                                derive_session_keys(&s_ident.secret, &remote_pub)
                            else {
                                continue;
                            };
                            if let Ok(dec) = decrypt_payload(
                                session_keys.receive.as_bytes(),
                                counter_in,
                                payload,
                            ) {
                                if let Ok(frame) = StreamFrame::decode(&dec) {
                                    let sock_clone = s_udp.clone();
                                    let c_clone = counter.clone();
                                    let my_pk = *s_ident.public_key.as_bytes();

                                    let reply_sink = move |resp_frame: StreamFrame| {
                                        let sock = sock_clone.clone();
                                        let c_val = c_clone.fetch_add(1, Ordering::SeqCst);
                                        let enc = encrypt_payload(
                                            session_keys.send.as_bytes(),
                                            c_val,
                                            &resp_frame.encode(),
                                        );
                                        if let Ok(b) = enc {
                                            let pkt = pack_message_v2(
                                                PacketType::Data,
                                                &s_tag,
                                                &my_pk,
                                                c_val,
                                                &b,
                                            );
                                            tokio::spawn(async move {
                                                let _ = sock.send_to(&pkt, sender_addr).await;
                                            });
                                        }
                                    };

                                    let _ = bridge.process_frame(frame, reply_sink).await;
                                }
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });

    // 4. Start StealthStreamClient on client side (listening on random TCP port)
    let local_bridge_port = {
        let temp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        temp.local_addr().unwrap().port()
    };

    let client = StealthStreamClient::new(
        local_bridge_port,
        server_addr,
        ssh_port,
        swarm_topic,
        client_identity.clone(),
        *server_identity.public_key.as_bytes(),
    );

    tokio::spawn(async move {
        let _ = client.run().await;
    });

    // Give the listener 50ms to bind
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 5. Connect as an SSH client to 127.0.0.1:local_bridge_port
    let mut ssh_client = TcpStream::connect(format!("127.0.0.1:{}", local_bridge_port))
        .await
        .expect("Konnte lokalen Stealth-Port nicht verbinden");

    // Read banner
    let mut banner_buf = [0u8; 64];
    let n = ssh_client.read(&mut banner_buf).await.unwrap();
    let banner = String::from_utf8_lossy(&banner_buf[..n]);
    println!(
        "Received banner over Mesh Stealth Tunnel: {}",
        banner.trim()
    );
    assert!(banner.contains("SSH-2.0-OpenSSH_9.6p1 S&B Stealth"));

    // Write client hello
    ssh_client
        .write_all(b"PING_OVER_MESH_STEALTH\n")
        .await
        .unwrap();

    // Read echo response
    let mut echo_buf = [0u8; 64];
    let n_echo = ssh_client.read(&mut echo_buf).await.unwrap();
    let echo_str = String::from_utf8_lossy(&echo_buf[..n_echo]);
    println!(
        "Received echo over Mesh Stealth Tunnel: {}",
        echo_str.trim()
    );
    assert_eq!(echo_str, "PING_OVER_MESH_STEALTH\n");

    println!("✓ E2E Mesh Stealth Ingress Bridge erfolgreich verifiziert!");
}
