//! Struct handlers - UDT APIs removed in idalib 0.9.0

use crate::error::ToolError;
use idalib::IDB;
use serde_json::Value;

const NOT_SUPPORTED: &str = "UDT/struct APIs removed in idalib 0.9.0";

pub fn handle_structs(
    _idb: &Option<IDB>,
    _offset: usize,
    _limit: usize,
    _filter: Option<&str>,
) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(NOT_SUPPORTED.to_string()))
}

pub fn handle_struct_info(_idb: &Option<IDB>, _struct_id: u32) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(NOT_SUPPORTED.to_string()))
}

pub fn handle_read_struct(_idb: &Option<IDB>, _addr: u64, _name: &str) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(NOT_SUPPORTED.to_string()))
}

pub fn handle_xrefs_to_field(_idb: &Option<IDB>, _struct_id: u32, _field_name: &str) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(NOT_SUPPORTED.to_string()))
}
