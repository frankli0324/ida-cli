//! Type handlers - functionality removed in idalib 0.9.0

use crate::error::ToolError;
use idalib::IDB;
use serde_json::Value;

const NOT_SUPPORTED: &str = "Type system APIs removed in idalib 0.9.0";

pub fn handle_local_types(
    _idb: &Option<IDB>,
    _offset: usize,
    _limit: usize,
    _filter: Option<&str>,
) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(NOT_SUPPORTED.to_string()))
}

pub fn handle_declare_type(
    _idb: &Option<IDB>,
    _decl: &str,
    _relaxed: bool,
    _replace: bool,
    _multi: bool,
) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(NOT_SUPPORTED.to_string()))
}

pub fn handle_declare_types(
    _idb: &Option<IDB>,
    _decls: Vec<String>,
    _replace: bool,
) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(NOT_SUPPORTED.to_string()))
}

pub fn handle_apply_types(
    _idb: &Option<IDB>,
    _addr: u64,
    _name: Option<&str>,
    _offset: Option<usize>,
    _type_str: &str,
) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(NOT_SUPPORTED.to_string()))
}

pub fn handle_guess_type(_idb: &Option<IDB>, _addr: u64) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(NOT_SUPPORTED.to_string()))
}

pub fn handle_infer_types(_idb: &Option<IDB>, _offset: usize) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(NOT_SUPPORTED.to_string()))
}

pub fn handle_set_function_prototype(_idb: &Option<IDB>, _addr: u64, _proto: &str) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(NOT_SUPPORTED.to_string()))
}

pub fn handle_rename_stack_variable(_idb: &Option<IDB>, _addr: u64, _idx: usize, _name: &str) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(NOT_SUPPORTED.to_string()))
}

pub fn handle_set_stack_variable_type(_idb: &Option<IDB>, _addr: u64, _idx: usize, _type_str: &str) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(NOT_SUPPORTED.to_string()))
}

pub fn handle_list_enums(_idb: &Option<IDB>, _offset: usize, _limit: usize) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(NOT_SUPPORTED.to_string()))
}

pub fn handle_create_enum(_idb: &Option<IDB>, _name: &str, _comment: Option<&str>) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(NOT_SUPPORTED.to_string()))
}

pub fn handle_declare_stack(_idb: &Option<IDB>, _addr: u64, _offset: i64, _name: &str, _type_str: Option<&str>) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(NOT_SUPPORTED.to_string()))
}

pub fn handle_delete_stack(_idb: &Option<IDB>, _addr: u64, _offset: i64) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(NOT_SUPPORTED.to_string()))
}

pub fn handle_stack_frame(_idb: &Option<IDB>, _addr: u64) -> Result<Value, ToolError> {
    Err(ToolError::IdaError(NOT_SUPPORTED.to_string()))
}
