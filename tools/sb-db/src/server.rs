use crate::db::Database;
use crate::protocol::{read_frame, write_frame, DbRequest, DbResponse};
use colored::*;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

pub struct DbServer {
    db: Arc<Database>,
}

impl DbServer {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    pub async fn run(&self, addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
        validate_loopback_bind(addr)?;
        let listener = TcpListener::bind(addr).await?;
        self.run_with_listener(listener).await
    }

    pub async fn run_with_listener(
        &self,
        listener: TcpListener,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let local_addr = listener.local_addr()?;
        validate_loopback_bind(local_addr)?;
        println!(
            "  {} Sovereign Database Server listening on {}",
            "✔".bright_green().bold(),
            local_addr.to_string().bright_cyan().bold()
        );

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let db = Arc::clone(&self.db);
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, db, peer_addr).await {
                            // Only log if not normal disconnect
                            if e.kind() != std::io::ErrorKind::ConnectionReset
                                && e.kind() != std::io::ErrorKind::UnexpectedEof
                            {
                                eprintln!(
                                    "  {} Error handling peer {}: {}",
                                    "⚠".bright_yellow(),
                                    peer_addr,
                                    e
                                );
                            }
                        }
                    });
                }
                Err(e) => {
                    eprintln!("  {} Listener accept error: {}", "✗".bright_red().bold(), e);
                }
            }
        }
    }
}

pub fn validate_loopback_bind(addr: SocketAddr) -> std::io::Result<()> {
    if !addr.ip().is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "sb-db TCP has no TLS or application authentication; refusing non-loopback bind {addr}"
            ),
        ));
    }
    Ok(())
}

async fn handle_connection(
    mut stream: TcpStream,
    db: Arc<Database>,
    peer_addr: SocketAddr,
) -> std::io::Result<()> {
    let (mut reader, mut writer) = stream.split();

    loop {
        let request: DbRequest = match read_frame(&mut reader).await {
            Ok(req) => req,
            Err(e)
                if e.kind() == std::io::ErrorKind::ConnectionReset
                    || e.kind() == std::io::ErrorKind::UnexpectedEof =>
            {
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        match request {
            DbRequest::Ping => {
                write_frame(&mut writer, &DbResponse::Pong).await?;
            }
            DbRequest::Get { key, path } => {
                let res = match path {
                    Some(p) => db.get_path(&key, &p),
                    None => db.get(&key),
                };
                write_frame(&mut writer, &DbResponse::Value(res)).await?;
            }
            DbRequest::Set {
                key,
                value,
                ttl_secs,
            } => {
                let res = match ttl_secs {
                    Some(secs) => db.set_with_ttl(&key, &value, Duration::from_secs(secs)),
                    None => db.set(&key, &value),
                };
                match res {
                    Ok(_) => write_frame(&mut writer, &DbResponse::Success).await?,
                    Err(e) => write_frame(&mut writer, &DbResponse::Error(e)).await?,
                }
            }

            DbRequest::SetPath { key, path, value } => match db.set_path(&key, &path, value) {
                Ok(_) => write_frame(&mut writer, &DbResponse::Success).await?,
                Err(e) => write_frame(&mut writer, &DbResponse::Error(e)).await?,
            },
            DbRequest::Delete { key } => match db.delete(&key) {
                Ok(deleted) => {
                    let resp = if deleted {
                        DbResponse::Success
                    } else {
                        DbResponse::Value(None)
                    };
                    write_frame(&mut writer, &resp).await?;
                }
                Err(e) => write_frame(&mut writer, &DbResponse::Error(e)).await?,
            },
            DbRequest::Scan { prefix } => {
                let pairs = db.scan(&prefix);
                write_frame(&mut writer, &DbResponse::ScanResult(pairs)).await?;
            }
            DbRequest::CreateIndex { prefix, field } => match db.create_index(&prefix, &field) {
                Ok(_) => write_frame(&mut writer, &DbResponse::Success).await?,
                Err(e) => write_frame(&mut writer, &DbResponse::Error(e)).await?,
            },
            DbRequest::DropIndex { prefix, field } => match db.drop_index(&prefix, &field) {
                Ok(_) => write_frame(&mut writer, &DbResponse::Success).await?,
                Err(e) => write_frame(&mut writer, &DbResponse::Error(e)).await?,
            },
            DbRequest::Find {
                prefix,
                field,
                value,
            } => {
                let results = db.find(&prefix, &field, &value);
                write_frame(&mut writer, &DbResponse::FindResult(results)).await?;
            }
            DbRequest::Transaction { tx } => match db.commit(tx) {
                Ok(_) => write_frame(&mut writer, &DbResponse::Success).await?,
                Err(e) => write_frame(&mut writer, &DbResponse::Error(e)).await?,
            },
            DbRequest::Compact => match db.compact() {
                Ok(bytes) => write_frame(&mut writer, &DbResponse::CompactSuccess(bytes)).await?,
                Err(e) => write_frame(&mut writer, &DbResponse::Error(e)).await?,
            },
            DbRequest::Stats => match db.stats() {
                Ok(stats) => write_frame(&mut writer, &DbResponse::Stats(stats)).await?,
                Err(e) => write_frame(&mut writer, &DbResponse::Error(e)).await?,
            },
            DbRequest::Watch { pattern } => {
                let mut rx = db.watch();
                write_frame(&mut writer, &DbResponse::Success).await?;

                // Stream events until client disconnects or channel closes
                loop {
                    tokio::select! {
                        event_res = rx.recv() => {
                            match event_res {
                                Ok(event) => {
                                    if event.matches_pattern(&pattern) {
                                        if let Err(e) = write_frame(&mut writer, &DbResponse::Event(event)).await {
                                            return Err(e);
                                        }
                                    }
                                }
                                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                                    eprintln!("  {} Client {} lagged {} events", "⚠".bright_yellow(), peer_addr, skipped);
                                }
                                Err(broadcast::error::RecvError::Closed) => {
                                    return Ok(());
                                }
                            }
                        }
                        // Check if client sent another request or disconnected
                        client_probe = read_frame::<_, DbRequest>(&mut reader) => {
                            match client_probe {
                                Ok(_) => {}
                                Err(e) => return Err(e),
                            }
                        }
                    }
                }
            }
        }
    }
}
