//! Memory handlers - patch APIs removed in idalib 0.9.0

use crate::error::ToolError;
use idalib::IDB;
use serde_json::Value;

const NOT_SUPPORTED: &str = "Byte patching APIs removed in idalib 0.9.0";

pub fn handle_patch_bytes(
    _idb: &Option<IDB>,
    _addr: u64,
    _bytes: Vec<u8>,
) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(NOT_SUPPORTED.to_string()))
}

pub fn handle_assemble_line(
    _idb: &Option<IDB>,
    _addr: u64,
    _line: &str,
) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(NOT_SUPPORTED.to_string()))
}

pub fn handle_get_bytes(_idb: &Option<IDB>, _addr: u64, _size: usize) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(NOT_SUPPORTED.to_string()))
}

pub fn handle_patch_asm(_idb: &Option<IDB>, _addr: u64, _line: &str) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(NOT_SUPPORTED.to_string()))
}

pub fn handle_read_int(_idb: &Option<IDB>, _addr: u64, _size: usize) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(NOT_SUPPORTED.to_string()))
}
