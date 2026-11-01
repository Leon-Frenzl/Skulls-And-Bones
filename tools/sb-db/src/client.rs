use crate::db::DbStats;
use crate::event::DbEvent;
use crate::protocol::{read_frame, write_frame, DbRequest, DbResponse};
use crate::transaction::Transaction;
use serde::de::DeserializeOwned;
use std::io;
use std::net::SocketAddr;
use tokio::net::TcpStream;

use tokio::io::{AsyncRead, AsyncWrite};

pub struct DbClient<S = TcpStream> {
    stream: S,
}

impl DbClient<TcpStream> {
    /// Connect to a Sovereign Database Server at the given socket address
    pub async fn connect(addr: SocketAddr) -> io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        Ok(Self { stream })
    }

    /// Connect to a Sovereign Database Server via string (e.g. "127.0.0.1:58830")
    pub async fn connect_str(addr: &str) -> io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        Ok(Self { stream })
    }
}

impl<S> DbClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Construct a DbClient from an arbitrary stream (e.g. CrossMeshStream, DuplexStream, TLS)
    pub fn from_stream(stream: S) -> Self {
        Self { stream }
    }

    async fn execute(&mut self, req: DbRequest) -> io::Result<DbResponse> {
        write_frame(&mut self.stream, &req).await?;
        let resp: DbResponse = read_frame(&mut self.stream).await?;
        if let DbResponse::Error(err) = resp {
            return Err(io::Error::new(io::ErrorKind::Other, err));
        }
        Ok(resp)
    }

    /// Send a Ping and verify Pong response
    pub async fn ping(&mut self) -> io::Result<()> {
        match self.execute(DbRequest::Ping).await? {
            DbResponse::Pong => Ok(()),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unexpected response to Ping: {:?}", other),
            )),
        }
    }

    /// Retrieve a JSON value by key
    pub async fn get(&mut self, key: &str) -> io::Result<Option<serde_json::Value>> {
        match self
            .execute(DbRequest::Get {
                key: key.to_string(),
                path: None,
            })
            .await?
        {
            DbResponse::Value(val) => Ok(val),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unexpected response to Get: {:?}", other),
            )),
        }
    }

    /// Retrieve and deserialize a typed value by key
    pub async fn get_typed<T: DeserializeOwned>(&mut self, key: &str) -> io::Result<Option<T>> {
        match self.get(key).await? {
            Some(val) => serde_json::from_value(val)
                .map(Some)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            None => Ok(None),
        }
    }

    /// Retrieve a nested value at dot-notation path
    pub async fn get_path(
        &mut self,
        key: &str,
        path: &str,
    ) -> io::Result<Option<serde_json::Value>> {
        match self
            .execute(DbRequest::Get {
                key: key.to_string(),
                path: Some(path.to_string()),
            })
            .await?
        {
            DbResponse::Value(val) => Ok(val),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unexpected response to GetPath: {:?}", other),
            )),
        }
    }

    /// Retrieve and deserialize a nested typed value at dot-notation path
    pub async fn get_path_typed<T: DeserializeOwned>(
        &mut self,
        key: &str,
        path: &str,
    ) -> io::Result<Option<T>> {
        match self.get_path(key, path).await? {
            Some(val) => serde_json::from_value(val)
                .map(Some)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            None => Ok(None),
        }
    }

    /// Set a key-value pair
    pub async fn set(&mut self, key: &str, value: serde_json::Value) -> io::Result<()> {
        match self
            .execute(DbRequest::Set {
                key: key.to_string(),
                value,
                ttl_secs: None,
            })
            .await?
        {
            DbResponse::Success => Ok(()),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unexpected response to Set: {:?}", other),
            )),
        }
    }

    /// Set a key-value pair with TTL in seconds
    pub async fn set_with_ttl(
        &mut self,
        key: &str,
        value: serde_json::Value,
        ttl_secs: u64,
    ) -> io::Result<()> {
        match self
            .execute(DbRequest::Set {
                key: key.to_string(),
                value,
                ttl_secs: Some(ttl_secs),
            })
            .await?
        {
            DbResponse::Success => Ok(()),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unexpected response to SetWithTtl: {:?}", other),
            )),
        }
    }

    /// Mutate a nested field via dot-notation path
    pub async fn set_path(
        &mut self,
        key: &str,
        path: &str,
        value: serde_json::Value,
    ) -> io::Result<()> {
        match self
            .execute(DbRequest::SetPath {
                key: key.to_string(),
                path: path.to_string(),
                value,
            })
            .await?
        {
            DbResponse::Success => Ok(()),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unexpected response to SetPath: {:?}", other),
            )),
        }
    }

    /// Delete a key
    pub async fn delete(&mut self, key: &str) -> io::Result<bool> {
        match self
            .execute(DbRequest::Delete {
                key: key.to_string(),
            })
            .await?
        {
            DbResponse::Success => Ok(true),
            DbResponse::Value(None) => Ok(false),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unexpected response to Delete: {:?}", other),
            )),
        }
    }

    /// Scan all keys starting with prefix
    pub async fn scan(&mut self, prefix: &str) -> io::Result<Vec<(String, serde_json::Value)>> {
        match self
            .execute(DbRequest::Scan {
                prefix: prefix.to_string(),
            })
            .await?
        {
            DbResponse::ScanResult(pairs) => Ok(pairs),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unexpected response to Scan: {:?}", other),
            )),
        }
    }

    /// Create a secondary index on a dot-notation path
    pub async fn create_index(&mut self, prefix: &str, field: &str) -> io::Result<()> {
        match self
            .execute(DbRequest::CreateIndex {
                prefix: prefix.to_string(),
                field: field.to_string(),
            })
            .await?
        {
            DbResponse::Success => Ok(()),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unexpected response to CreateIndex: {:?}", other),
            )),
        }
    }

    /// Drop a secondary index
    pub async fn drop_index(&mut self, prefix: &str, field: &str) -> io::Result<()> {
        match self
            .execute(DbRequest::DropIndex {
                prefix: prefix.to_string(),
                field: field.to_string(),
            })
            .await?
        {
            DbResponse::Success => Ok(()),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unexpected response to DropIndex: {:?}", other),
            )),
        }
    }

    /// Find documents matching an index value in O(1)
    pub async fn find(
        &mut self,
        prefix: &str,
        field: &str,
        value: serde_json::Value,
    ) -> io::Result<Vec<(String, serde_json::Value)>> {
        match self
            .execute(DbRequest::Find {
                prefix: prefix.to_string(),
                field: field.to_string(),
                value,
            })
            .await?
        {
            DbResponse::FindResult(pairs) => Ok(pairs),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unexpected response to Find: {:?}", other),
            )),
        }
    }

    /// Commit an atomic multi-operation transaction
    pub async fn transaction(&mut self, tx: Transaction) -> io::Result<()> {
        match self.execute(DbRequest::Transaction { tx }).await? {
            DbResponse::Success => Ok(()),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unexpected response to Transaction: {:?}", other),
            )),
        }
    }

    /// Trigger database compaction
    pub async fn compact(&mut self) -> io::Result<u64> {
        match self.execute(DbRequest::Compact).await? {
            DbResponse::CompactSuccess(bytes) => Ok(bytes),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unexpected response to Compact: {:?}", other),
            )),
        }
    }

    /// Fetch database statistics
    pub async fn stats(&mut self) -> io::Result<DbStats> {
        match self.execute(DbRequest::Stats).await? {
            DbResponse::Stats(s) => Ok(s),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unexpected response to Stats: {:?}", other),
            )),
        }
    }

    /// Subscribe to live Change Data Capture (CDC) events matching pattern
    pub async fn watch(mut self, pattern: &str) -> io::Result<DbEventStream<S>> {
        write_frame(
            &mut self.stream,
            &DbRequest::Watch {
                pattern: pattern.to_string(),
            },
        )
        .await?;
        let resp: DbResponse = read_frame(&mut self.stream).await?;
        match resp {
            DbResponse::Success => Ok(DbEventStream {
                stream: self.stream,
            }),
            DbResponse::Error(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unexpected response to Watch: {:?}", other),
            )),
        }
    }
}

pub struct DbEventStream<S = TcpStream> {
    stream: S,
}

impl<S> DbEventStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Read the next Change Data Capture event from the stream
    pub async fn next_event(&mut self) -> io::Result<DbEvent> {
        match read_frame::<_, DbResponse>(&mut self.stream).await? {
            DbResponse::Event(e) => Ok(e),
            DbResponse::Error(err) => Err(io::Error::new(io::ErrorKind::Other, err)),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unexpected response in event stream: {:?}", other),
            )),
        }
    }
}
