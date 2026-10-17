//! State management module
//!
//! Manages application state including mode, protocol, and connection information

pub mod app_state;
pub mod client;
pub mod client_handles;
pub mod easy;
pub mod exchange_history;
pub mod intercepts;
pub mod llm_activity;
pub mod machine;
pub mod server;
pub mod server_handles;
pub mod sqlite;
pub mod task;

pub use app_state::{AccessLogOwner, AppState};
pub use client::{ClientConnectionState, ClientId, ClientInstance, ClientStatus};
pub use client_handles::{ClientCommand, ClientHandle, ClientSendOutcome};
pub use easy::{EasyId, EasyInstance, EasyStatus};
pub use machine::StateMachine;
pub use server::{
    ConnectionState, ProtocolConnectionInfo, ProtocolState, ServerId, ServerInstance, ServerStatus,
};
pub use server_handles::ServerHandle;
pub use sqlite::{DatabaseId, DatabaseInstance, DatabaseManager, DatabaseOwner, QueryResult};
pub use task::{ScheduledTask, TaskExecutionResult, TaskId, TaskScope, TaskStatus, TaskType};
