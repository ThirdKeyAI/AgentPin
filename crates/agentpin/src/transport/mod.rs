//! Transport binding modules (spec Section 13).
//!
//! Framework-agnostic helpers for extracting and formatting AgentPin
//! credentials across common transport protocols.

pub mod grpc;
pub mod http;
pub mod mcp;
pub mod websocket;
