use sb_mesh::bridge::{CrossMeshEnvelope, CrossMeshPayload};
use sb_mesh::client::{MeshClient, MeshClientConfig};
use sb_mesh::crypto::{
    decrypt_payload, derive_session_keys, derive_swarm_tag, encrypt_payload, pack_message_v2,
    unpack_header_v2, PacketType,
};
use sb_mesh::fec::{FecEncoder, StreamFecReceiver};
use sb_mesh::identity::NodeIdentity;
use sha2::Digest;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use x25519_dalek::PublicKey;

async fn send_anchor_envelope(
    socket: &UdpSocket,
    client_addr: std::net::SocketAddr,
    keys: &sb_mesh::crypto::SessionKeys,
    counter: &AtomicU64,
    tag: &[u8; 8],
    anchor_key: &PublicKey,
    envelope: CrossMeshEnvelope,
) -> Vec<u8> {
    let counter = counter.fetch_add(1, Ordering::SeqCst);
    let encrypted = encrypt_payload(keys.send.as_bytes(), counter, &envelope.encode()).unwrap();
    let packet = pack_message_v2(
        PacketType::Data,
        tag,
        anchor_key.as_bytes(),
        counter,
        &encrypted,
    );
    socket.send_to(&packet, client_addr).await.unwrap();
    packet
}

#[tokio::test]
async fn network_stream_authenticates_anchor_and_transfers_both_directions() {
    let anchor_identity = NodeIdentity::generate();
    let client_identity = Arc::new(NodeIdentity::generate());
    let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let anchor_addr = server_socket.local_addr().unwrap();
    let anchor_public_key = anchor_identity.public_key;
    let anchor_node_id = anchor_identity.node_id.clone();
    let client_for_server = client_identity.clone();
    let server_for_task = server_socket.clone();
    let anchor_public_for_task = anchor_public_key;
    let anchor_id_for_task = anchor_node_id.clone();

    let server_task = tokio::spawn(async move {
        let keys =
            derive_session_keys(&anchor_identity.secret, &client_for_server.public_key).unwrap();
        let expected_tag = derive_swarm_tag("sbm-swarm-app-mesh");
        let mut buf = [0u8; 65535];
        let (len, client_addr) = server_for_task.recv_from(&mut buf).await.unwrap();
        let (ptype, tag, client_key, counter, encrypted) = unpack_header_v2(&buf[..len]).unwrap();
        assert_eq!(ptype, PacketType::Data);
        assert_eq!(tag, expected_tag);
        assert_eq!(client_key, *client_for_server.public_key.as_bytes());
        let plaintext = decrypt_payload(keys.receive.as_bytes(), counter, encrypted).unwrap();
        let connect = CrossMeshEnvelope::decode(&plaintext).unwrap();
        assert_eq!(connect.source_mesh, "app-mesh");
        assert_eq!(connect.source_node_id, client_for_server.node_id);
        assert!(matches!(
            connect.payload,
            CrossMeshPayload::StreamConnectFec {
                target_port: 58830,
                data_symbols: 8,
                parity_symbols: 5,
            }
        ));

        let counter = AtomicU64::new(1);
        let ack = CrossMeshEnvelope::new(
            "database-mesh",
            &anchor_id_for_task,
            "app-mesh",
            None,
            CrossMeshPayload::StreamAck { session_id: 91 },
        );
        let _ = send_anchor_envelope(
            &server_for_task,
            client_addr,
            &keys,
            &counter,
            &expected_tag,
            &anchor_public_for_task,
            ack,
        )
        .await;
        let response = b"read";
        let profile = sb_mesh::fec::FecProfile {
            data_symbols: 8,
            parity_symbols: 5,
        };
        let symbols = FecEncoder::new(response, profile.data_symbols)
            .generate_fec_block(profile.parity_symbols);
        let response_digest = sb_mesh::fec::stream_fec_block_digest(1, response);
        let mut recovery = StreamFecReceiver::default();
        for index in [11, 1, 8, 4, 10, 2, 9, 6] {
            let symbol = &symbols[index];
            let envelope = CrossMeshEnvelope::new(
                "database-mesh",
                &anchor_id_for_task,
                "app-mesh",
                None,
                CrossMeshPayload::StreamDataFec {
                    session_id: 91,
                    block_id: 1,
                    symbol_index: index as u16,
                    data_symbols: profile.data_symbols as u16,
                    parity_symbols: profile.parity_symbols as u16,
                    original_len: response.len() as u32,
                    block_digest: response_digest,
                    coefficients: symbol.coefficients.clone(),
                    data: symbol.payload.clone(),
                },
            );
            let packet = send_anchor_envelope(
                &server_for_task,
                client_addr,
                &keys,
                &counter,
                &expected_tag,
                &anchor_public_for_task,
                envelope,
            )
            .await;
            if index == 1 {
                server_for_task.send_to(&packet, client_addr).await.unwrap();
            }
        }
        let response_block_end = CrossMeshEnvelope::new(
            "database-mesh",
            &anchor_id_for_task,
            "app-mesh",
            None,
            CrossMeshPayload::StreamFecBlockEnd {
                session_id: 91,
                block_id: 1,
                data_symbols: profile.data_symbols as u16,
                parity_symbols: profile.parity_symbols as u16,
                original_len: response.len() as u32,
                block_digest: response_digest,
            },
        );
        let _ = send_anchor_envelope(
            &server_for_task,
            client_addr,
            &keys,
            &counter,
            &expected_tag,
            &anchor_public_for_task,
            response_block_end,
        )
        .await;
        let response_close = CrossMeshEnvelope::new(
            "database-mesh",
            &anchor_id_for_task,
            "app-mesh",
            None,
            CrossMeshPayload::StreamCloseFec {
                session_id: 91,
                final_block_id: 1,
                stream_digest: sha2::Sha256::digest(response).into(),
            },
        );
        let _ = send_anchor_envelope(
            &server_for_task,
            client_addr,
            &keys,
            &counter,
            &expected_tag,
            &anchor_public_for_task,
            response_close,
        )
        .await;

        let mut recovered = None;
        let mut received_response_ack = false;
        let mut received_upload_block_end = false;
        let mut saw_initial_upload_block_end = false;
        let mut repaired_symbol_indices = Vec::new();
        while !received_response_ack || !received_upload_block_end {
            let (len, _) = timeout(Duration::from_secs(3), server_for_task.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            let (ptype, tag, client_key, packet_counter, encrypted) =
                unpack_header_v2(&buf[..len]).unwrap();
            assert_eq!(ptype, PacketType::Data);
            assert_eq!(tag, expected_tag);
            assert_eq!(client_key, *client_for_server.public_key.as_bytes());
            let plaintext =
                decrypt_payload(keys.receive.as_bytes(), packet_counter, encrypted).unwrap();
            let data = CrossMeshEnvelope::decode(&plaintext).unwrap();
            match data.payload {
                CrossMeshPayload::StreamFecBlockAck {
                    session_id: 91,
                    block_id: 1,
                    origin_node_id,
                } if origin_node_id == anchor_id_for_task => received_response_ack = true,
                CrossMeshPayload::StreamDataFec {
                    block_id,
                    symbol_index,
                    data_symbols,
                    parity_symbols,
                    original_len,
                    block_digest,
                    coefficients,
                    data,
                    ..
                } => {
                    if saw_initial_upload_block_end {
                        repaired_symbol_indices.push(symbol_index);
                    }
                    if !saw_initial_upload_block_end
                        && [0, 1, 2, 3, 4, 5].contains(&(symbol_index as usize))
                    {
                        continue;
                    }
                    let blocks = recovery
                        .add_indexed_symbol(
                            block_id,
                            Some(symbol_index as usize),
                            data_symbols as usize,
                            parity_symbols as usize,
                            original_len as usize,
                            block_digest,
                            sb_mesh::fec::CodedPacket::new(coefficients, data),
                        )
                        .unwrap();
                    recovered = blocks.into_iter().next().or(recovered);
                }
                CrossMeshPayload::StreamFecBlockEnd {
                    session_id: 91,
                    block_id: 1,
                    data_symbols,
                    parity_symbols,
                    original_len,
                    block_digest,
                } => {
                    saw_initial_upload_block_end = true;
                    let missing = recovery
                        .missing_symbol_indices(
                            1,
                            data_symbols as usize,
                            parity_symbols as usize,
                            original_len as usize,
                            block_digest,
                        )
                        .unwrap();
                    let control = match missing {
                        Some((symbol_indices, repair_round)) => {
                            CrossMeshPayload::StreamFecRepairRequest {
                                session_id: 91,
                                block_id: 1,
                                origin_node_id: client_for_server.node_id.clone(),
                                symbol_indices,
                                repair_round,
                            }
                        }
                        None => {
                            received_upload_block_end = true;
                            CrossMeshPayload::StreamFecBlockAck {
                                session_id: 91,
                                block_id: 1,
                                origin_node_id: client_for_server.node_id.clone(),
                            }
                        }
                    };
                    let response = CrossMeshEnvelope::new(
                        "database-mesh",
                        &anchor_id_for_task,
                        "app-mesh",
                        None,
                        control,
                    );
                    let _ = send_anchor_envelope(
                        &server_for_task,
                        client_addr,
                        &keys,
                        &counter,
                        &expected_tag,
                        &anchor_public_for_task,
                        response,
                    )
                    .await;
                }
                other => panic!("Unexpected client envelope: {other:?}"),
            }
        }
        assert_eq!(recovered.as_deref(), Some(b"write".as_slice()));
        assert_eq!(repaired_symbol_indices, (0..6).collect::<Vec<_>>());
        let (len, _) = timeout(Duration::from_secs(3), server_for_task.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let (_, _, _, packet_counter, encrypted) = unpack_header_v2(&buf[..len]).unwrap();
        let plaintext =
            decrypt_payload(keys.receive.as_bytes(), packet_counter, encrypted).unwrap();
        let close = CrossMeshEnvelope::decode(&plaintext).unwrap();
        let expected_digest: [u8; 32] = sha2::Sha256::digest(b"write").into();
        assert!(
            matches!(
                close.payload,
                CrossMeshPayload::StreamCloseFec {
                    final_block_id: 1,
                    stream_digest,
                    ..
                } if stream_digest == expected_digest
            ),
            "expected successful upload close, got {:?}",
            close.payload
        );
    });

    let client = MeshClient::connect_with_anchor_pin(
        MeshClientConfig {
            mesh_name: "app-mesh".to_string(),
            swarm_topic: "sbm-swarm-app-mesh".to_string(),
            anchor_addr,
            identity: client_identity,
            local_bind_port: None,
        },
        anchor_public_key,
        anchor_node_id,
    )
    .await
    .unwrap();
    let mut stream = client
        .open_cross_mesh_transfer("database-mesh", 58830, None, 5)
        .await
        .unwrap();
    let mut incoming = [0u8; 4];
    timeout(Duration::from_secs(3), stream.recv(&mut incoming))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&incoming, b"read");
    let mut replayed = [0u8; 1];
    assert!(
        timeout(Duration::from_millis(100), stream.recv(&mut replayed))
            .await
            .is_err()
    );
    stream.send(b"write").await.unwrap();
    assert!(stream.send(b"!").await.is_err());
    timeout(Duration::from_secs(3), server_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn premature_size_declared_upload_sends_abort_close_not_fec_digest() {
    let anchor_identity = NodeIdentity::generate();
    let client_identity = Arc::new(NodeIdentity::generate());
    let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let anchor_addr = server_socket.local_addr().unwrap();
    let anchor_public_key = anchor_identity.public_key;
    let anchor_node_id = anchor_identity.node_id.clone();
    let client_for_server = client_identity.clone();
    let server_for_task = server_socket.clone();
    let anchor_public_for_task = anchor_public_key;
    let anchor_id_for_task = anchor_node_id.clone();

    let server_task = tokio::spawn(async move {
        let keys =
            derive_session_keys(&anchor_identity.secret, &client_for_server.public_key).unwrap();
        let expected_tag = derive_swarm_tag("sbm-swarm-app-mesh");
        let mut buf = [0u8; 65535];
        let (len, client_addr) = server_for_task.recv_from(&mut buf).await.unwrap();
        let (_, _, _, received_counter, encrypted) = unpack_header_v2(&buf[..len]).unwrap();
        let plaintext =
            decrypt_payload(keys.receive.as_bytes(), received_counter, encrypted).unwrap();
        let connect = CrossMeshEnvelope::decode(&plaintext).unwrap();
        assert!(matches!(
            connect.payload,
            CrossMeshPayload::StreamConnectFec { .. }
        ));

        let counter = AtomicU64::new(1);
        let ack = CrossMeshEnvelope::new(
            "database-mesh",
            &anchor_id_for_task,
            "app-mesh",
            None,
            CrossMeshPayload::StreamAck { session_id: 92 },
        );
        let _ = send_anchor_envelope(
            &server_for_task,
            client_addr,
            &keys,
            &counter,
            &expected_tag,
            &anchor_public_for_task,
            ack,
        )
        .await;

        let mut received_data = false;
        loop {
            let (len, _) = timeout(Duration::from_secs(3), server_for_task.recv_from(&mut buf))
                .await
                .expect("timed out waiting for the incomplete transfer close")
                .unwrap();
            let (_, _, _, received_counter, encrypted) = unpack_header_v2(&buf[..len]).unwrap();
            let plaintext =
                decrypt_payload(keys.receive.as_bytes(), received_counter, encrypted).unwrap();
            let envelope = CrossMeshEnvelope::decode(&plaintext).unwrap();
            match envelope.payload {
                CrossMeshPayload::StreamDataFec { .. } => received_data = true,
                CrossMeshPayload::StreamFecBlockEnd {
                    session_id: 92,
                    block_id,
                    ..
                } => {
                    let ack = CrossMeshEnvelope::new(
                        "database-mesh",
                        &anchor_id_for_task,
                        "app-mesh",
                        None,
                        CrossMeshPayload::StreamFecBlockAck {
                            session_id: 92,
                            block_id,
                            origin_node_id: client_for_server.node_id.clone(),
                        },
                    );
                    let _ = send_anchor_envelope(
                        &server_for_task,
                        client_addr,
                        &keys,
                        &counter,
                        &expected_tag,
                        &anchor_public_for_task,
                        ack,
                    )
                    .await;
                }
                CrossMeshPayload::StreamClose { session_id } => {
                    assert_eq!(session_id, 92);
                    assert!(received_data, "partial data should precede the abort close");
                    break;
                }
                CrossMeshPayload::StreamCloseFec { .. } => {
                    panic!("incomplete upload must not report a successful FEC close");
                }
                payload => panic!("unexpected payload during incomplete upload: {payload:?}"),
            }
        }
    });

    let client = MeshClient::connect_with_anchor_pin(
        MeshClientConfig {
            mesh_name: "app-mesh".to_string(),
            swarm_topic: "sbm-swarm-app-mesh".to_string(),
            anchor_addr,
            identity: client_identity,
            local_bind_port: None,
        },
        anchor_public_key,
        anchor_node_id,
    )
    .await
    .unwrap();
    let mut stream = client
        .open_cross_mesh_transfer("database-mesh", 58830, None, 8)
        .await
        .unwrap();
    stream.send(b"abc").await.unwrap();
    drop(stream);

    timeout(Duration::from_secs(5), server_task)
        .await
        .unwrap()
        .unwrap();
}
