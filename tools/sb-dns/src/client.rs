use hickory_proto::op::Message;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn query_server(server: SocketAddr, request: &Message) -> Result<Message, String> {
    let request_bytes = request
        .to_vec()
        .map_err(|error| format!("DNS query encoding failed: {error}"))?;
    let bind_addr = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = tokio::net::UdpSocket::bind(bind_addr)
        .await
        .map_err(|error| format!("DNS client socket bind failed: {error}"))?;
    socket
        .send_to(&request_bytes, server)
        .await
        .map_err(|error| format!("DNS query send failed: {error}"))?;
    let mut response_bytes = vec![0u8; 4096];
    let (length, source) = tokio::time::timeout(
        Duration::from_secs(3),
        socket.recv_from(&mut response_bytes),
    )
    .await
    .map_err(|_| format!("DNS query to {server} timed out"))?
    .map_err(|error| format!("DNS response receive failed: {error}"))?;
    if source != server {
        return Err(format!(
            "DNS response came from unexpected source {source}, expected {server}"
        ));
    }
    let response = Message::from_vec(&response_bytes[..length])
        .map_err(|error| format!("DNS response parsing failed: {error}"))?;
    validate_response(request, &response)?;
    if response.truncation {
        return query_server_tcp(server, &request_bytes, request).await;
    }
    Ok(response)
}

async fn query_server_tcp(
    server: SocketAddr,
    request_bytes: &[u8],
    request: &Message,
) -> Result<Message, String> {
    let mut stream = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::TcpStream::connect(server),
    )
    .await
    .map_err(|_| format!("DNS TCP connection to {server} timed out"))?
    .map_err(|error| format!("DNS TCP connection to {server} failed: {error}"))?;
    let length = u16::try_from(request_bytes.len())
        .map_err(|_| "DNS query is too large for TCP framing".to_string())?;
    let bytes = tokio::time::timeout(Duration::from_secs(3), async {
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(request_bytes).await?;
        let mut prefix = [0u8; 2];
        stream.read_exact(&mut prefix).await?;
        let response_length = u16::from_be_bytes(prefix) as usize;
        if response_length > 4096 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "DNS TCP response exceeds the configured size limit",
            ));
        }
        let mut bytes = vec![0u8; response_length];
        stream.read_exact(&mut bytes).await?;
        Ok::<_, std::io::Error>(bytes)
    })
    .await
    .map_err(|_| "DNS TCP query timed out".to_string())?
    .map_err(|error| format!("DNS TCP query failed: {error}"))?;
    let response = Message::from_vec(&bytes)
        .map_err(|error| format!("DNS TCP response parsing failed: {error}"))?;
    validate_response(request, &response)?;
    Ok(response)
}

fn validate_response(request: &Message, response: &Message) -> Result<(), String> {
    crate::protocol::validate_dns_response(
        request,
        response,
        request.id,
        "DNS response does not match the outstanding query",
    )
}
