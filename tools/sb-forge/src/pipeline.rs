//! Pipeline Engine Typen
use serde::{Deserialize, Serialize};

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct RunRecord {
    pub id: String,
    pub pipeline: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub status: RunStatus,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub enum RunStatus {
    Running,
    Success,
    Failed,
    RolledBack,
}
